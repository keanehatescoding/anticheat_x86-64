/*
 * ac_report_url_test.c -- regression test for #67: AC_REPORT_URL must
 * accept a "unix:///path/to/socket" destination (AF_UNIX SOCK_STREAM)
 * as an alternative to the existing "host:port" plain-TCP form, without
 * changing how the existing TCP form is parsed.
 *
 * Exercises ac_report_parse_url() directly -- pure string parsing, no
 * socket needed -- so this can run anywhere `make ci` does. The actual
 * AF_UNIX connect()/send()/recv() path this feeds into is exercised
 * against a real server/ac_server.py instance in server/test_server.sh's
 * --unix-socket block instead, the same split ac_report_status_test.c
 * already uses for the HTTP status-line parser vs. the real wire format.
 *
 * Pulls anticheat_daemon.c in as-is (renaming its main() out of the way)
 * to test the real ac_report_parse_url(), not a duplicated copy.
 *
 * Build: make ac-report-url-test
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
    struct ac_report_dest dest;

    /* existing host:port form must keep working exactly as before */
    CHECK(ac_report_parse_url("example.com:8787", &dest) == 0 &&
              !dest.is_unix &&
              strcmp(dest.host, "example.com") == 0 &&
              strcmp(dest.port, "8787") == 0,
          "host:port parses to a TCP destination");

    CHECK(ac_report_parse_url("127.0.0.1:8787", &dest) == 0 &&
              !dest.is_unix &&
              strcmp(dest.host, "127.0.0.1") == 0 &&
              strcmp(dest.port, "8787") == 0,
          "literal IPv4:port parses to a TCP destination");

    /* an IPv6 literal has multiple colons -- strrchr() (last colon) is
     * what picks out the port, same as before this change */
    CHECK(ac_report_parse_url("::1:8787", &dest) == 0 &&
              !dest.is_unix &&
              strcmp(dest.host, "::1") == 0 &&
              strcmp(dest.port, "8787") == 0,
          "last colon splits host:port even with extra colons in host");

    CHECK(ac_report_parse_url("no-colon-here", &dest) == -1,
          "a URL with no colon and no unix:// prefix is rejected");

    /* the new unix:// form */
    CHECK(ac_report_parse_url("unix:///run/anticheat/ac_server.sock",
                               &dest) == 0 &&
              dest.is_unix &&
              strcmp(dest.sock_path, "/run/anticheat/ac_server.sock") == 0,
          "unix:///path parses to a unix-socket destination");

    CHECK(ac_report_parse_url("unix:///run/anticheat/ac_server.sock",
                               &dest) == 0 &&
              strcmp(dest.host, "localhost") == 0,
          "unix-socket destination gets a fixed \"localhost\" Host: "
          "header placeholder");

    /* a relative-looking path is still just whatever follows the
     * prefix -- ac_report_parse_url() doesn't require a leading slash,
     * matching how the daemon has no other opinion on filesystem
     * layout (e.g. AC_BASELINE_DIR) */
    CHECK(ac_report_parse_url("unix://relative.sock", &dest) == 0 &&
              dest.is_unix &&
              strcmp(dest.sock_path, "relative.sock") == 0,
          "unix:// with a relative-looking path is still accepted");

    CHECK(ac_report_parse_url("unix://", &dest) == -1,
          "unix:// with an empty path is rejected");
    /* #24: a host interpolated verbatim into "Host:" must not carry CR/LF */
    CHECK(ac_report_parse_url("evil\r\nInjected: x:8787", &dest) == -1,
          "a host containing CRLF is rejected");
    CHECK(ac_report_parse_url("evil\nhost:8787", &dest) == -1,
          "a host containing LF is rejected");
    CHECK(ac_report_parse_url("[::1\r\nx]:8787", &dest) == -1,
          "a bracketed IPv6 host containing CRLF is rejected");

    /* the header-safety helper itself: AC_REPORT_KEY never passes through
     * the URL parser, so ac_report() screens it separately before
     * formatting "Authorization: Bearer %s" */
    CHECK(ac_header_value_safe("normal-key-123") == 1,
          "a plain header value is accepted");
    CHECK(ac_header_value_safe("a\rb") == 0,
          "a header value containing CR is rejected");
    CHECK(ac_header_value_safe("a\nb") == 0,
          "a header value containing LF is rejected");
    CHECK(ac_header_value_safe("a\r\nb") == 0,
          "a header value containing CRLF is rejected");


    {
        /* sizeof(dest.sock_path) mirrors sizeof(sun_path) -- build a
         * path exactly at, and one past, that bound. */
        char toolong[600];
        size_t cap = sizeof(dest.sock_path);
        char url[7 + sizeof(toolong)];
        size_t i;

        for (i = 0; i + 1 < sizeof(toolong); i++)
            toolong[i] = 'a';
        toolong[cap] = '\0';   /* exactly `cap` bytes, i.e. one too long
                                   for a NUL-terminated sun_path */
        snprintf(url, sizeof(url), "unix://%s", toolong);
        CHECK(ac_report_parse_url(url, &dest) == -1,
              "a unix socket path at sizeof(sun_path) (no room for the "
              "NUL) is rejected, not silently truncated");

        toolong[cap - 1] = '\0';   /* exactly cap - 1 bytes: the longest
                                       path that still fits */
        snprintf(url, sizeof(url), "unix://%s", toolong);
        CHECK(ac_report_parse_url(url, &dest) == 0 && dest.is_unix &&
                  strlen(dest.sock_path) == cap - 1,
              "a unix socket path at exactly the longest length that "
              "fits is accepted");
    }

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    fprintf(stderr, "all checks passed\n");
    return 0;
}
