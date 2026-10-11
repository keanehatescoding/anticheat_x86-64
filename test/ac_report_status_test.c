/*
 * ac_report_status_test.c -- regression test for #57: ac_report() must
 * decide HTTP delivery success/failure by parsing the response status
 * line, not by scanning the whole raw response for " 200"/" 201"
 * substrings (which a header like "Content-Length: 200" on an actual
 * error response could satisfy).
 *
 * Also covers coderabbit findings on the #57 fix itself:
 *   - the strict status-line parser must reject a malformed line like
 *     "HTTP/1.1 +200 OK" (a leading sign on the status code, which plain
 *     sscanf("%d") would still happily parse as a real 200);
 *   - ...and "HTTP/1.1 200X OK" (a stray byte glued onto the status
 *     code with no delimiter);
 *   - ...and anything other than HTTP/1.x with exactly one minor-version
 *     digit, e.g. "HTTP/2.0 200 OK" or "HTTP/01.1 200 OK" -- ac_report()
 *     only ever speaks plain HTTP/1.x, so those can't be genuine
 *     responses from the configured report server.
 *
 * And #29: the status line must be read to its end, not assumed to have
 * arrived whole in the first read(), and ac_json_escape() must leave the
 * report body valid UTF-8 whatever bytes a comm or path holds.
 *
 * Pulls anticheat_daemon.c in as-is (renaming its main() out of the way)
 * to test the real ac_http_status_code(), not a duplicated copy.
 *
 * Build: make ac-report-status-test
 */
#define main ac_daemon_unused_main
#include "../src/anticheat_daemon.c"
#undef main

static int failures;

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s\n", msg); \
        failures++; \
    } else { \
        fprintf(stderr, "PASS: %s\n", msg); \
    } \
} while (0)

int main(void)
{
    /* well-formed lines */
    CHECK(ac_http_status_code("HTTP/1.1 200 OK\r\n") == 200,
          "200 OK parses to 200");
    CHECK(ac_http_status_code("HTTP/1.1 201 Created\r\n") == 201,
          "201 Created parses to 201");
    CHECK(ac_http_status_code("HTTP/1.1 404 Not Found\r\n") == 404,
          "404 Not Found parses to 404");
    CHECK(ac_http_status_code("HTTP/1.0 500 Internal Server Error\r\n") == 500,
          "HTTP/1.0 500 parses to 500");

    /* the original #57 bug: a substring match on the raw response would
     * have found " 200" inside this header on a real 404 response */
    CHECK(ac_http_status_code(
              "HTTP/1.1 404 Not Found\r\nContent-Length: 200\r\n\r\n") == 404,
          "404 with a 'Content-Length: 200' header still parses to 404, "
          "not 200");

    /* the coderabbit finding on the #57 fix: a leading sign must not be
     * accepted as part of a valid 3-digit status code */
    CHECK(ac_http_status_code("HTTP/1.1 +200 OK\r\n") == -1,
          "a leading '+' on the status code is rejected, not parsed as 200");
    CHECK(ac_http_status_code("HTTP/1.1 -50 OK\r\n") == -1,
          "a leading '-' on the status code is rejected");

    /* other malformed lines must fail closed (-1), not be silently
     * misparsed into some in-range code */
    CHECK(ac_http_status_code("HTTP/1.1 2000 OK\r\n") == -1,
          "a four-digit status code is rejected");
    CHECK(ac_http_status_code("HTTP/2 200 OK\r\n") == -1,
          "a status line missing the minor version is rejected");
    CHECK(ac_http_status_code("garbage 200 not a status line\r\n") == -1,
          "a response not starting with 'HTTP/' is rejected");
    CHECK(ac_http_status_code("") == -1, "an empty response is rejected");

    /* a coderabbit finding on the #57 fix: only HTTP/1.x with exactly
     * one minor-version digit is a genuine response ac_report() could
     * actually receive; anything else must fail closed too */
    CHECK(ac_http_status_code("HTTP/2.0 200 OK\r\n") == -1,
          "HTTP/2.0 is rejected, not treated as an HTTP/1.x response");
    CHECK(ac_http_status_code("HTTP/01.1 200 OK\r\n") == -1,
          "a multi-digit (zero-padded) major version is rejected");
    CHECK(ac_http_status_code("HTTP/1.11 200 OK\r\n") == -1,
          "a multi-digit minor version is rejected");

    /* a second coderabbit finding on the #57 fix: a non-space byte glued
     * directly onto the three status-code digits (no delimiter) must not
     * be silently accepted as if that byte weren't there */
    CHECK(ac_http_status_code("HTTP/1.1 200X OK\r\n") == -1,
          "a non-space suffix glued onto the status code is rejected");
    CHECK(ac_http_status_code("HTTP/1.1 200") == 200,
          "a status code with no reason phrase or trailing CRLF "
          "(end-of-buffer right after the code) is still accepted");
    CHECK(ac_http_status_code("HTTP/1.1 200\r\n") == 200,
          "a status code immediately followed by CRLF (empty reason "
          "phrase) is still accepted");

    /* #29: a status line split across reads is still read whole */
    {
        int sv[2];
        char resp[64];
        pid_t pid;

        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0,
              "socketpair for the split status line test");
        pid = fork();
        CHECK(pid >= 0, "fork for the split status line test");
        if (pid == 0) {
            close(sv[0]);
            if (write(sv[1], "HTTP/1.1 2", 10) != 10)
                _exit(1);
            usleep(100 * 1000);
            if (write(sv[1], "01 Created\r\nX: y\r\n", 18) != 18)
                _exit(1);
            _exit(0);
        }
        close(sv[1]);
        CHECK(ac_read_status_line(sv[0], resp, sizeof(resp), 3) > 0 &&
              strchr(resp, '\n') != NULL &&
              ac_http_status_code(resp) == 201,
              "a status line split across two segments is read through its "
              "newline and parses to 201");
        close(sv[0]);
        waitpid(pid, NULL, 0);
    }
    {
        int sv[2];
        char resp[8];

        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0,
              "socketpair for the status line bounds tests");
        CHECK(write(sv[1], "HTTP/1.1 200 OK\r\n", 17) == 17,
              "queue a status line longer than the buffer");
        CHECK(ac_read_status_line(sv[0], resp, sizeof(resp), 3) == 7 &&
              strcmp(resp, "HTTP/1.") == 0,
              "a full buffer ends the read, NUL-terminated in bounds");
        close(sv[1]);
        CHECK(ac_read_status_line(sv[0], resp, sizeof(resp), 3) == 7 &&
              ac_read_status_line(sv[0], resp, sizeof(resp), 3) == 3 &&
              strcmp(resp, "K\r\n") == 0,
              "the rest drains, ending at the line's newline");
        CHECK(ac_read_status_line(sv[0], resp, sizeof(resp), 3) == 0 &&
              resp[0] == '\0',
              "a closed connection with no bytes returns 0 and an empty resp");
        close(sv[0]);
    }

    /* #29: ac_json_escape() and bytes >= 0x80 */
    {
        char out[64];

        ac_json_escape("caf\xc3\xa9 \xe2\x82\xac \xf0\x9f\x98\x80", out, sizeof(out));
        CHECK(strcmp(out, "caf\xc3\xa9 \xe2\x82\xac \xf0\x9f\x98\x80") == 0,
              "well-formed 2-, 3- and 4-byte UTF-8 passes through unchanged");
        ac_json_escape("a\xff" "b\x80" "c", out, sizeof(out));
        CHECK(strcmp(out, "a\\ufffdb\\ufffdc") == 0,
              "a byte that can't start a sequence, and a stray continuation "
              "byte, each become U+FFFD");
        ac_json_escape("\xc0\xaf", out, sizeof(out));
        CHECK(strcmp(out, "\\ufffd\\ufffd") == 0,
              "an overlong encoding is not passed through");
        ac_json_escape("\xed\xa0\x80", out, sizeof(out));
        CHECK(strcmp(out, "\\ufffd\\ufffd\\ufffd") == 0,
              "a UTF-16 surrogate is not passed through");
        ac_json_escape("x\xe2\x82", out, sizeof(out));
        CHECK(strcmp(out, "x\\ufffd\\ufffd") == 0,
              "a sequence cut off by the end of the string is replaced "
              "without reading past the NUL");
        ac_json_escape("q\"\\\n\x01", out, sizeof(out));
        CHECK(strcmp(out, "q\\\"\\\\\\n\\u0001") == 0,
              "ASCII escaping is unchanged");
    }
    {
        /* Truncation must not split a sequence: 4-byte characters into a
         * buffer that can't hold them all. */
        char out[16];
        size_t n;

        ac_json_escape("\xf0\x9f\x98\x80\xf0\x9f\x98\x80\xf0\x9f\x98\x80"
                       "\xf0\x9f\x98\x80", out, sizeof(out));
        n = strlen(out);
        CHECK(n > 0 && n < sizeof(out) && n % 4 == 0,
              "a truncated escape ends on a whole UTF-8 sequence");
    }

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    fprintf(stderr, "all checks passed\n");
    return 0;
}
