#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define JSON_STATIC
#define JSON_IMPLEMENTATION
#include "../json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define test_section(desc) \
    do { \
        printf("--------------- {%s} ---------------\n", desc);\
    } while (0);

#define test_assert(cond) \
    do { \
        int pass = cond; \
        printf("[%s] %s:%d: ", pass ? "PASS" : "FAIL", __FILE__, __LINE__);\
        printf((strlen(#cond) > 60 ? "%.47s...\n" : "%s\n"), #cond);\
        if (pass) pass_count++; else fail_count++; \
    } while (0)

#define test_token(t, content, typ, child, s)\
    {test_assert(!json_cmp(t, content));\
    test_assert((t)->type == (typ));\
    test_assert((t)->children == (child));\
    test_assert((t)->sub == (s));}

#define test_result()\
    do { \
        printf("======================================================\n"); \
        printf("== Result:  %3d Total   %3d Passed      %3d Failed  ==\n", \
                pass_count  + fail_count, pass_count, fail_count); \
        printf("======================================================\n"); \
    } while (0)

static int run_test(void)
{
    int pass_count = 0;
    int fail_count = 0;


    test_section("str")
    {
        struct json_iter iter;
        struct json_pair pair;
        char buffer[8];

        const char buf[] = "{\"name\":\"value\"}";
        iter = json_begin(buf, sizeof buf);

        iter = json_parse(&pair, &iter);
        test_assert(!iter.err);
        test_assert(!json_cmp(&pair.name, "name"));
        test_assert(!json_cmp(&pair.value, "value"));
        test_assert(pair.value.type == JSON_STRING);
        test_assert(pair.value.children == 0);
        test_assert(pair.value.sub == 0);
        test_assert(json_cpy(buffer, sizeof buffer, &pair.value) == 5);
        test_assert(!strcmp(&buffer[0], "value"));
    }

    test_section("num")
    {
        json_number num = 0;
        struct json_iter iter;
        struct json_pair pair;
        const char buf[] = "\n{\n\"test\":13\n}\n";
        iter = json_begin(buf, sizeof buf);

        iter = json_parse(&pair, &iter);
        test_assert(!iter.err);
        test_assert(!json_cmp(&pair.name, "test"));
        test_assert(!json_cmp(&pair.value, "13"));
        test_assert(pair.value.type == JSON_NUMBER);
        test_assert(json_convert(&num, &pair.value) == JSON_NUMBER);
        test_assert(num == 13.0);
    }

    test_section("negnum")
    {
        json_number num = 0;
        struct json_pair pair;
        struct json_iter iter;
        const char buf[] = "{\"name\":-1234}";
        iter = json_begin(buf, sizeof buf);

        iter = json_parse(&pair, &iter);
        test_assert(!iter.err);
        test_assert(!json_cmp(&pair.name, "name"));
        test_assert(!json_cmp(&pair.value, "-1234"));
        test_assert(pair.value.type == JSON_NUMBER);
        test_assert(json_convert(&num, &pair.value) == JSON_NUMBER);
        test_assert(num == -1234.0);
    }

    test_section("fracnum")
    {
        json_number num = 0;
        struct json_iter iter;
        struct json_pair pair;
        const char buf[] = "{\"name\":1234.5678}";
        iter = json_begin(buf, sizeof buf);

        iter = json_parse(&pair, &iter);
        test_assert(!iter.err);
        test_assert(!json_cmp(&pair.name, "name"));
        test_assert(!json_cmp(&pair.value, "1234.5678"));
        test_assert(pair.value.type == JSON_NUMBER);
        test_assert(json_convert(&num, &pair.value) == JSON_NUMBER);
        test_assert(num == 1234.5678);
    }

    test_section("negfracnum")
    {
        json_number num = 0;
        struct json_iter iter;
        struct json_pair pair;
        const char buf[] = "{\"name\":-1234.5678}";
        iter = json_begin(buf, sizeof buf);

        iter = json_parse(&pair, &iter);
        test_assert(!iter.err);
        test_assert(!json_cmp(&pair.name, "name"));
        test_assert(!json_cmp(&pair.value, "-1234.5678"));
        test_assert(pair.value.type == JSON_NUMBER);
        test_assert(json_convert(&num, &pair.value) == JSON_NUMBER);
        test_assert(num == -1234.5678);
    }

    test_section("exponent")
    {
        json_number num = 0;
        struct json_iter iter;
        struct json_pair pair;
        const char buf[] = "{\"name\":2e+2}";
        iter = json_begin(buf, sizeof buf);

        iter = json_parse(&pair, &iter);
        test_assert(!iter.err);
        test_assert(!json_cmp(&pair.name, "name"));
        test_assert(!json_cmp(&pair.value, "2e+2"));
        test_assert(pair.value.type == JSON_NUMBER);
        test_assert(json_convert(&num, &pair.value) == JSON_NUMBER);
        test_assert(num == 200.0);
    }

    test_section("negexponent")
    {
        json_number num = 0;
        struct json_iter iter;
        struct json_pair pair;
        const char buf[] = "{\"name\":-1234e-2}";
        iter = json_begin(buf, sizeof buf);

        iter = json_parse(&pair, &iter);
        test_assert(!iter.err);
        test_assert(!json_cmp(&pair.name, "name"));
        test_assert(!json_cmp(&pair.value, "-1234e-2"));
        test_assert(pair.value.type == JSON_NUMBER);
        test_assert(json_convert(&num, &pair.value) == JSON_NUMBER);
        test_assert(num == -12.34);
    }

    test_section("smallexp")
    {
        json_number num = 0;
        struct json_iter iter;
        struct json_pair pair;
        const char buf[] = "{\"name\":2.567e-4}";
        iter = json_begin(buf, sizeof buf);

        iter = json_parse(&pair, &iter);
        test_assert(!iter.err);
        test_assert(!json_cmp(&pair.name, "name"));
        test_assert(!json_cmp(&pair.value, "2.567e-4"));
        test_assert(pair.value.type == JSON_NUMBER);
        test_assert(json_convert(&num, &pair.value) == JSON_NUMBER);
        test_assert(num >= 0.0002567 && num <= 0.0002568);
    }

    test_section("utf8")
    {
        struct json_iter iter;
        struct json_pair pair;
        const char buf[] = "{\"name\":\"$¢€𤪤\"}";
        iter = json_begin(buf, sizeof buf);

        iter = json_parse(&pair, &iter);
        test_assert(!iter.err);
        test_assert(!json_cmp(&pair.name, "name"));
        test_assert(!json_cmp(&pair.value, "$¢€𤪤"));
        test_assert(pair.value.type == JSON_STRING);
    }

    test_section("map")
    {
        struct json_iter iter;
        struct json_pair pair;
        const char buf[] = "{\"name\":\"test\", \"age\":42, \"utf8\":\"äöü\", \"alive\":true}";
        iter = json_begin(buf, sizeof buf);

        iter = json_parse(&pair, &iter);
        test_assert(!iter.err);
        test_assert(!json_cmp(&pair.name, "name"));
        test_assert(!json_cmp(&pair.value, "test"));
        test_assert(pair.value.type == JSON_STRING);

        iter = json_parse(&pair, &iter);
        test_assert(!iter.err);
        test_assert(!json_cmp(&pair.name, "age"));
        test_assert(!json_cmp(&pair.value, "42"));
        test_assert(pair.value.type == JSON_NUMBER);

        iter = json_parse(&pair, &iter);
        test_assert(!iter.err);
        test_assert(!json_cmp(&pair.name, "utf8"));
        test_assert(!json_cmp(&pair.value, "äöü"));
        test_assert(pair.value.type == JSON_STRING);

        iter = json_parse(&pair, &iter);
        test_assert(!iter.err);
        test_assert(!json_cmp(&pair.name, "alive"));
        test_assert(!json_cmp(&pair.value, "true"));
        test_assert(pair.value.type == JSON_TRUE);
    }

    test_section("array_root")
    {
        int i = 1;
        json_number num;
        struct json_token tok;
        struct json_iter iter;
        const char *toks[] = {0, "1.0", "2.0", "3.0", "4.0"};

        const char buf[] = "[1.0, 2.0, 3.0, 4.0 ]";
        iter = json_begin(buf, sizeof(buf));
        iter = json_read(&tok, &iter);
        while (iter.src) {
            test_assert(!json_cmp(&tok, toks[i]));
            test_assert(json_convert(&num, &tok) == JSON_NUMBER);
            test_assert((json_number)i == num);
            iter = json_read(&tok, &iter);
            i++;
        }
    }

    test_section("RTFC7159_1")
    {
        struct json_iter iter;
        struct json_pair pair;
        char buffer[8];

        const char buf[] = "\"name\"=\"value\"";
        iter = json_begin(buf, sizeof buf);
        iter = json_parse(&pair, &iter);

        test_assert(!iter.err);
        test_assert(!json_cmp(&pair.name, "name"));
        test_assert(!json_cmp(&pair.value, "value"));
        test_assert(pair.value.type == JSON_STRING);
        test_assert(pair.value.children == 0);
        test_assert(pair.value.sub == 0);
        test_assert(json_cpy(buffer, sizeof buffer, &pair.value) == 5);
        test_assert(!strcmp(&buffer[0], "value"));
    }

    test_section("RTFC7159_2")
    {
        struct json_iter iter;
        struct json_token tok;

        const char buf[] = "1.0";
        iter = json_begin(buf, sizeof(buf));
        iter = json_read(&tok, &iter);
        test_assert(!iter.err);
        test_assert(tok.type == JSON_NUMBER);
        test_assert(!json_cmp(&tok, "1.0"));
    }

    test_section("RTFC7159_3")
    {
        struct json_iter iter;
        struct json_token tok;

        const char buf[] = "true";
        iter = json_begin(buf, sizeof(buf));
        iter = json_read(&tok, &iter);
        test_assert(!iter.err);
        test_assert(tok.type == JSON_TRUE);
    }

    test_section("RTFC7159_4")
    {
        struct json_iter iter;
        struct json_token tok;

        const char buf[] = "false";
        iter = json_begin(buf, sizeof(buf));
        iter = json_read(&tok, &iter);
        test_assert(!iter.err);
        test_assert(tok.type == JSON_FALSE);
    }

    test_section("RTFC7159_5")
    {
        struct json_iter iter;
        struct json_token tok;

        const char buf[] = "null";
        iter = json_begin(buf, sizeof(buf));
        iter = json_read(&tok, &iter);
        test_assert(!iter.err);
        test_assert(tok.type == JSON_NULL);
    }

    test_section("extension")
    {
        struct json_iter iter;
        struct json_pair pair;

        const char buf[] = "\"name\"=\"value\", \"value\":5";
        iter = json_begin(buf, sizeof(buf));
        iter = json_parse(&pair, &iter);
        test_assert(!iter.err);
        test_assert(pair.name.type == JSON_STRING);
        test_assert(pair.value.type == JSON_STRING);
        iter = json_parse(&pair, &iter);
        test_assert(!iter.err);
        test_assert(pair.name.type == JSON_STRING);
        test_assert(pair.value.type == JSON_NUMBER);
    }

    test_section("array")
    {
        int i = 1;
        json_number num;
        struct json_token tok;
        struct json_iter iter;
        struct json_pair pair;

        const char buf[] = "{\"list\":[ 1.0, 2.0, 3.0, 4.0 ]}";
        iter = json_begin(buf, sizeof buf);

        iter = json_parse(&pair, &iter);
        test_assert(!iter.err);
        test_assert(!json_cmp(&pair.name, "list"));
        test_assert(!json_cmp(&pair.value, "[ 1.0, 2.0, 3.0, 4.0 ]"));
        test_assert(pair.value.type == JSON_ARRAY);
        test_assert(pair.value.children == 4);
        test_assert(pair.value.sub == 4);

        iter = json_begin(pair.value.str, pair.value.len);
        iter = json_read(&tok, &iter);
        while (iter.src) {
            test_assert(json_convert(&num, &tok) == JSON_NUMBER);
            test_assert((json_number)i == num);
            iter = json_read(&tok, &iter);
            i++;
        }
    }

    test_section("sub")
    {
        json_number num = 0;
        struct json_iter iter;
        struct json_pair pair;
        const char buf[] = "{\"sub\":{\"a\":1234.5678}}";
        iter = json_begin(buf, sizeof buf);

        iter = json_parse(&pair, &iter);
        test_assert(!iter.err);
        test_assert(!json_cmp(&pair.name, "sub"));
        test_assert(!json_cmp(&pair.value, "{\"a\":1234.5678}"));
        test_assert(pair.value.type == JSON_OBJECT);
        test_assert(pair.value.children == 1);
        test_assert(pair.value.sub == 2);

        iter = json_begin(pair.value.str, pair.value.len);
        iter = json_parse(&pair, &iter);
        test_assert(!iter.err);
        test_assert(!json_cmp(&pair.name, "a"));
        test_assert(!json_cmp(&pair.value, "1234.5678"));
        test_assert(pair.value.type == JSON_NUMBER);

        test_assert(json_convert(&num, &pair.value) == JSON_NUMBER);
        test_assert(num == 1234.5678);
    }

    test_section("subarray")
    {
        int i = 0;
        struct json_token tok;
        struct json_iter iter;
        struct json_pair pair;
        const char check[] = "1234";
        const char buf[] = "{\"sub\":{\"a\":[1,2,3,4]}}";
        iter = json_begin(buf, sizeof buf);

        iter = json_parse(&pair, &iter);
        test_assert(!iter.err);
        test_assert(!json_cmp(&pair.name, "sub"));
        test_assert(!json_cmp(&pair.value, "{\"a\":[1,2,3,4]}"));
        test_assert(pair.value.type == JSON_OBJECT);
        test_assert(pair.value.children == 1);
        test_assert(pair.value.sub == 6);

        iter = json_begin(pair.value.str, pair.value.len);
        iter = json_parse(&pair, &iter);
        test_assert(!iter.err);
        test_assert(!json_cmp(&pair.name, "a"));
        test_assert(!json_cmp(&pair.value, "[1,2,3,4]"));
        test_assert(pair.value.type == JSON_ARRAY);
        test_assert(pair.value.children == 4);
        test_assert(pair.value.sub == 4);

        iter = json_begin(pair.value.str, pair.value.len);
        iter = json_read(&tok, &iter);
        while (iter.src) {
            test_assert(tok.str[0] == check[i++]);
            iter = json_read(&tok, &iter);
        }
    }

    test_section("list")
    {
        struct json_iter iter;
        struct json_pair pair;
        const char buf[] = "{\"sub\":{\"a\":\"b\"}, \"list\":{\"c\":\"d\"}}";
        iter = json_begin(buf, sizeof buf);

        iter = json_parse(&pair, &iter);
        test_assert(!iter.err);
        test_assert(!json_cmp(&pair.name, "sub"));
        test_assert(!json_cmp(&pair.value, "{\"a\":\"b\"}"));
        test_assert(pair.value.type == JSON_OBJECT);
        test_assert(pair.value.children == 1);
        test_assert(pair.value.sub == 2);

        iter = json_parse(&pair, &iter);
        test_assert(!iter.err);
        test_assert(!json_cmp(&pair.name, "list"));
        test_assert(!json_cmp(&pair.value, "{\"c\":\"d\"}"));
        test_assert(pair.value.type == JSON_OBJECT);
        test_assert(pair.value.children == 1);
        test_assert(pair.value.sub == 2);
    }

    test_section("table")
    {
        struct json_iter iter;
        struct json_pair pair;
        const char buf[] =
            "{\"sub\":{\"a\": \"b\"}, \"list\":[1,2,3,4], \"a\":true, \"b\": \"0a1b2\"}";
        iter = json_begin(buf, sizeof buf);

        iter = json_parse(&pair, &iter);
        test_assert(!iter.err);
        test_assert(!json_cmp(&pair.name, "sub"));
        test_assert(!json_cmp(&pair.value, "{\"a\": \"b\"}"));
        test_assert(pair.value.type == JSON_OBJECT);
        test_assert(pair.value.children == 1);
        test_assert(pair.value.sub == 2);

        iter = json_parse(&pair, &iter);
        test_assert(!iter.err);
        test_assert(!json_cmp(&pair.name, "list"));
        test_assert(!json_cmp(&pair.value, "[1,2,3,4]"));
        test_assert(pair.value.type == JSON_ARRAY);
        test_assert(pair.value.children == 4);
        test_assert(pair.value.sub == 4);

        iter = json_parse(&pair, &iter);
        test_assert(!iter.err);
        test_assert(!json_cmp(&pair.name, "a"));
        test_assert(!json_cmp(&pair.value, "true"));
        test_assert(pair.value.type == JSON_TRUE);

        iter = json_parse(&pair, &iter);
        test_assert(!iter.err);
        test_assert(!json_cmp(&pair.name, "b"));
        test_assert(!json_cmp(&pair.value, "0a1b2"));
        test_assert(pair.value.type == JSON_STRING);
    }

    test_section("children")
    {
        struct json_iter iter;
        struct json_pair pair;
        const char buf[] = "{\"b\": {\"a\": {\"b\":5}, \"b\":[1,2,3,4],"
            "\"c\":\"test\", \"d\":true, \"e\":false, \"f\":null, \"g\":10},"
            "\"a\": [{\"b\":5}, [1,2,3,4], \"test\", true, false, null, 10]}";
        iter = json_begin(buf, sizeof buf);

        iter = json_parse(&pair, &iter);
        test_assert(!iter.err);
        test_assert(!json_cmp(&pair.name, "b"));
        test_assert(pair.value.type == JSON_OBJECT);
        test_assert(pair.value.children == 7);
        test_assert(pair.value.sub == 20);

        iter = json_parse(&pair, &iter);
        test_assert(!iter.err);
        test_assert(!json_cmp(&pair.name, "a"));
        test_assert(pair.value.type == JSON_ARRAY);
        test_assert(pair.value.children == 7);
        test_assert(pair.value.sub == 13);
    }

    test_section("arrayofarray")
    {
        int i = 1;
        struct json_iter iter;
        struct json_pair pair;
        struct json_token tok;
        const char buf[] = "{\"coord\":[[[1,2], [3,4], [5,6]]]}";
        iter = json_begin(buf, sizeof buf);

        iter = json_parse(&pair, &iter);
        test_assert(!iter.err);
        test_assert(!json_cmp(&pair.name, "coord"));
        test_assert(pair.value.type == JSON_ARRAY);
        test_assert(pair.value.children == 1);

        iter = json_begin(pair.value.str, pair.value.len);
        iter = json_read(&tok, &iter);
        test_assert(tok.type == JSON_ARRAY);
        test_assert(tok.children == 3);

        iter = json_begin(tok.str, tok.len);
        iter = json_read(&tok, &iter);
        while (!iter.err && iter.src) {
            struct json_iter it;
            test_assert(tok.type == JSON_ARRAY);
            test_assert(tok.children == 2);
            it = json_begin(tok.str, tok.len);
            it = json_read(&tok, &it);
            while (!it.err && it.src) {
                json_number n;
                test_assert(tok.type == JSON_NUMBER);
                json_convert(&n, &tok);
                test_assert(n == i++);
                it = json_read(&tok, &it);
            }
            iter = json_read(&tok, &iter);
        }
    }

    test_section("totalcount")
    {
        const char buf[] =
            "{\"sub\":{\"a\": \"b\"}, \"list\":[1,2,3,4], \"a\":true, \"b\": \"0a1b2\"}";
        const char buf2[] = "{\"coord\":[[[1,2], [3,4], [5,6]]]}";
        const char buf3[] = "{\"list\":[ 1.0, 2.0, 3.0, 4.0 ]}";
        const char buf4[] = "{\"name\":\"test\", \"age\":42, \"utf8\":\"äöü\", \"alive\":true}";
        test_assert(json_num(buf, sizeof(buf)) == 14);
        test_assert(json_num(buf2, sizeof(buf2)) == 12);
        test_assert(json_num(buf3, sizeof(buf3)) == 6);
        test_assert(json_num(buf4, sizeof(buf4)) == 8);
    }

    test_section("parse")
    {
        /* Beware parser take about sizeof(struct json_iter) * JSON_MAX_DEPTH bytes of memory */
        const char buf[] = "{\"sub\":{\"a\": \"b\"}, \"list\":[1,2,3,4], \"a\":true, \"b\": \"0a1b2\"}";
        struct json_parser p = {0};
        while (json_load(&p, buf, sizeof(buf)))
            p.toks = realloc(p.toks, (size_t)p.cap * sizeof(struct json_token));

        test_assert(p.err == JSON_OK);
        test_token(&p.toks[0], "sub", JSON_STRING, 0, 0);
        test_token(&p.toks[1], "{\"a\": \"b\"}", JSON_OBJECT, 1, 2);
        test_token(&p.toks[2], "a", JSON_STRING, 0, 0);
        test_token(&p.toks[3], "b", JSON_STRING, 0, 0);
        test_token(&p.toks[4], "list", JSON_STRING, 0, 0);
        test_token(&p.toks[5], "[1,2,3,4]", JSON_ARRAY, 4, 4);
        test_token(&p.toks[6], "1", JSON_NUMBER, 0, 0);
        test_token(&p.toks[7], "2", JSON_NUMBER, 0, 0);
        test_token(&p.toks[8], "3", JSON_NUMBER, 0, 0);
        test_token(&p.toks[9], "4", JSON_NUMBER, 0, 0);
        test_token(&p.toks[10], "a", JSON_STRING, 0, 0);
        test_token(&p.toks[11], "true", JSON_TRUE, 0, 0);
        test_token(&p.toks[12], "b", JSON_STRING, 0, 0);
        test_token(&p.toks[13], "0a1b2", JSON_STRING, 0, 0);
        test_assert(p.cnt == 14);
        free(p.toks);
    }

    test_section("load")
    {
        int count = 0;
        struct json_token toks[14] = {{0}};
        const char buf[] =
            "{\"sub\":{\"a\": \"b\"}, \"list\":[1,2,3,4], \"a\":true, \"b\": \"0a1b2\"}";

        count = json_num(buf, sizeof(buf));
        test_assert(count <= 14);

        {struct json_parser p = {0};
        p.toks = toks; p.cap = 14;
        json_load(&p, buf, sizeof(buf));
        test_assert(p.err == JSON_OK);

        if (p.err == JSON_OK) {
            test_token(&toks[0], "sub", JSON_STRING, 0, 0);
            test_token(&toks[1], "{\"a\": \"b\"}", JSON_OBJECT, 1, 2);
            test_token(&toks[2], "a", JSON_STRING, 0, 0);
            test_token(&toks[3], "b", JSON_STRING, 0, 0);
            test_token(&toks[4], "list", JSON_STRING, 0, 0);
            test_token(&toks[5], "[1,2,3,4]", JSON_ARRAY, 4, 4);
            test_token(&toks[6], "1", JSON_NUMBER, 0, 0);
            test_token(&toks[7], "2", JSON_NUMBER, 0, 0);
            test_token(&toks[8], "3", JSON_NUMBER, 0, 0);
            test_token(&toks[9], "4", JSON_NUMBER, 0, 0);
            test_token(&toks[10], "a", JSON_STRING, 0, 0);
            test_token(&toks[11], "true", JSON_TRUE, 0, 0);
            test_token(&toks[12], "b", JSON_STRING, 0, 0);
            test_token(&toks[13], "0a1b2", JSON_STRING, 0, 0);
            test_assert(p.cnt == 14);
        }}
    }

    test_section("load_array_root")
    {
        struct json_token toks[14] = {{0}};
        const char buf[] = "[ 1.0, 2.0, 3.0, 4.0 ]";

        struct json_parser p = {0};
        p.toks = toks; p.cap = 14;
        json_load(&p, buf, sizeof(buf));

        test_assert(p.err == JSON_OK);
        if (p.err == JSON_OK) {
            test_token(&toks[0], "1.0", JSON_NUMBER, 0, 0);
            test_token(&toks[1], "2.0", JSON_NUMBER, 0, 0);
            test_token(&toks[2], "3.0", JSON_NUMBER, 0, 0);
            test_token(&toks[3], "4.0", JSON_NUMBER, 0, 0);
            test_assert(p.cnt == 4);
        }
    }

    test_section("load_invalid_array")
    {
        struct json_token toks[14] = {{0}};
        const char buf[] = "[\"Extra close\"]]";

        struct json_parser p = {0};
        p.toks = toks; p.cap = 14;
        json_load(&p, buf, sizeof(buf));
        test_assert(p.err != JSON_OK);
    }

    test_section("empty")
    {
        int count = 0;
        struct json_token toks[14] = {{0}};
        const char buf[] =
            "{\"sub\":{\"a\": \"b\"}, \"list\":[1,2,3,4], \"a\":true, \"b\": \"0a1b2\"}";

        count = json_num(buf, sizeof(buf));
        test_assert(count == 14);

        {struct json_parser p = {0};
        p.toks = toks; p.cap = 14;
        json_load(&p, buf, sizeof(buf));
        test_assert(p.err == JSON_OK);

        if (p.err == JSON_OK) {
            test_token(&toks[0], "sub", JSON_STRING, 0, 0);
            test_token(&toks[1], "{\"a\": \"b\"}", JSON_OBJECT, 1, 2);
            test_token(&toks[2], "a", JSON_STRING, 0, 0);
            test_token(&toks[3], "b", JSON_STRING, 0, 0);
            test_token(&toks[4], "list", JSON_STRING, 0, 0);
            test_token(&toks[5], "[1,2,3,4]", JSON_ARRAY, 4, 4);
            test_token(&toks[6], "1", JSON_NUMBER, 0, 0);
            test_token(&toks[7], "2", JSON_NUMBER, 0, 0);
            test_token(&toks[8], "3", JSON_NUMBER, 0, 0);
            test_token(&toks[9], "4", JSON_NUMBER, 0, 0);
            test_token(&toks[10], "a", JSON_STRING, 0, 0);
            test_token(&toks[11], "true", JSON_TRUE, 0, 0);
            test_token(&toks[12], "b", JSON_STRING, 0, 0);
            test_token(&toks[13], "0a1b2", JSON_STRING, 0, 0);
            test_assert(p.cnt == 14);
        }}
    }

    test_section("query_simple")
    {
        int cnt = 0;
        struct json_token toks[14] = {{0}};
        const char buf[] =
            "{\"sub\":{\"a\": \"b\"}, \"list\":[1,2,3,4], \"a\":true, \"b\": \"0a1b2\"}";

        cnt = json_num(buf, sizeof(buf));
        test_assert(cnt == 14);

        {struct json_parser p = {0};
        p.toks = toks; p.cap = 14;
        json_load(&p, buf, sizeof(buf));
        test_assert(p.err == JSON_OK);

        if (p.err == JSON_OK) {
            test_assert(p.cnt == 14);
            test_assert(json_query(toks, p.cnt, "list[0]") == &toks[6]);
            test_assert(json_query(toks, p.cnt, "list[3]") == &toks[9]);
            test_assert(json_query(toks, p.cnt, "sub.a") == &toks[3]);
            test_assert(json_query(toks, p.cnt, "b") == &toks[13]);
        }}
    }

    test_section("query_complex")
    {
        struct json_token toks[128];
        const char buf[] =
        "{\"map\":{"
            "\"entity\":["
                "{\"position\": {\"x\":1, \"y\":1}, \"size\":{\"w\":1,\"h\":1}},"
                "{\"position\": {\"x\":2, \"y\":2}, \"size\":{\"w\":2,\"h\":2}},"
                "{\"position\": {\"x\":3, \"y\":3}, \"size\":{\"w\":3,\"h\":3}},"
                "{\"position\": {\"x\":4, \"y\":4}, \"size\":{\"w\":4,\"h\":4}},"
                "{\"position\": {\"x\":5, \"y\":5}, \"size\":{\"w\":5,\"h\":5}}"
            "]"
        "}}";
        memset(toks, 0,  sizeof(toks));

        {struct json_parser p = {0};
        p.toks = toks; p.cap = 128;
        json_load(&p, buf, sizeof(buf));
        test_assert(p.err == JSON_OK);

        if (p.err == JSON_OK) {
            test_assert(json_query(toks, p.cnt, "map") == &toks[1]);
            test_assert(json_query(toks, p.cnt, "map.entity") == &toks[3]);
            test_assert(json_query(toks, p.cnt, "map.entity[0]") == &toks[4]);
            test_assert(json_query(toks, p.cnt, "map.entity[1]") == &toks[17]);
            test_assert(json_query(toks, p.cnt, "map.entity[2]") == &toks[30]);
            test_assert(json_query(toks, p.cnt, "map.entity[3]") == &toks[43]);
            test_assert(json_query(toks, p.cnt, "map.entity[4]") == &toks[56]);
            test_assert(json_query(toks, p.cnt, "map.entity[0].position.x") == &toks[8]);
            test_assert(json_query(toks, p.cnt, "map.entity[2].position.y") == &toks[36]);
            test_assert(json_query(toks, p.cnt, "map.entity[4].size.w") == &toks[66]);
            {
                struct json_token *tok = json_query(toks, p.cnt, "map.entity");
                test_assert(tok->children == 5);
            }
        }}
    }

    test_section("query_entangled")
    {
        struct json_token toks[128];
        const char buf[] = "{\"b\": {\"a\": {\"b\":5}, \"b\":[1,2,3,4],"
            "\"c\":\"test\", \"d\":true, \"e\":false, \"f\":null, \"g\":10},"
            "\"a\": [{\"b\":5}, [1,2,3,4], \"test\", true, false, null, 10]}";

        memset(toks, 0,  sizeof(toks));
        {struct json_parser p = {0};
        p.toks = toks; p.cap = 128;
        json_load(&p, buf, sizeof(buf));
        test_assert(p.err == JSON_OK);

        if (p.err == JSON_OK) {
            test_assert(json_query(toks, p.cnt, "b") == &toks[1]);
            test_assert(json_query(toks, p.cnt, "b.a") == &toks[3]);
            test_assert(json_query(toks, p.cnt, "b.a.b") == &toks[5]);
            test_assert(json_query(toks, p.cnt, "b.b") == &toks[7]);
            test_assert(json_query(toks, p.cnt, "b.c") == &toks[13]);
            test_assert(json_query(toks, p.cnt, "b.d") == &toks[15]);
            test_assert(json_query(toks, p.cnt, "b.e") == &toks[17]);
            test_assert(json_query(toks, p.cnt, "b.f") == &toks[19]);
            test_assert(json_query(toks, p.cnt, "a[0]") == &toks[24]);
            test_assert(json_query(toks, p.cnt, "a[0].b") == &toks[26]);
            test_assert(json_query(toks, p.cnt, "a[1]") == &toks[27]);
            test_assert(json_query(toks, p.cnt, "a[1][0]") == &toks[28]);
            test_assert(json_query(toks, p.cnt, "a[1][1]") == &toks[29]);
            test_assert(json_query(toks, p.cnt, "a[1][2]") == &toks[30]);
            test_assert(json_query(toks, p.cnt, "a[1][3]") == &toks[31]);
            test_assert(json_query(toks, p.cnt, "a[2]") == &toks[32]);
            test_assert(json_query(toks, p.cnt, "a[3]") == &toks[33]);
            test_assert(json_query(toks, p.cnt, "a[4]") == &toks[34]);
            test_assert(json_query(toks, p.cnt, "a[5]") == &toks[35]);
            test_assert(json_query(toks, p.cnt, "a[6]") == &toks[36]);
        }}
    }

    test_section("query_sub")
    {
        struct json_token toks[128];
        struct json_token *entity;
        struct json_token *position;
        struct json_token *size;

        const char buf[] =
        "{\"map\":{"
            "\"entity\":["
                "{\"position\": {\"x\":1, \"y\":1}, \"size\":{\"w\":1,\"h\":1}},"
                "{\"position\": {\"x\":2, \"y\":2}, \"size\":{\"w\":2,\"h\":2}},"
                "{\"position\": {\"x\":3, \"y\":3}, \"size\":{\"w\":3,\"h\":3}},"
                "{\"position\": {\"x\":4, \"y\":4}, \"size\":{\"w\":4,\"h\":4}},"
                "{\"position\": {\"x\":5, \"y\":5}, \"size\":{\"w\":5,\"h\":5}}"
            "]"
        "}}";
        memset(toks, 0,  sizeof(toks));

        {struct json_parser p = {0};
        p.toks = toks; p.cap = 128;
        json_load(&p, buf, sizeof(buf));
        test_assert(p.err == JSON_OK);

        if (p.err == JSON_OK) {
            entity = json_query(toks, p.cnt, "map.entity[2]");
            test_assert(entity == &toks[30]);

            position = json_query(entity, entity->sub, "position");
            test_assert(position == &toks[32]);

            size = json_query(entity, entity->sub, "size");
            test_assert(size == &toks[38]);
            {
                struct json_token *x, *y;
                x = json_query(position, position->sub, "x");
                y = json_query(position, position->sub, "y");
                test_assert(x == &toks[34]);
                test_assert(y == &toks[36]);
            }
            {
                struct json_token *w, *h;
                w = json_query(size, size->sub, "w");
                h = json_query(size, size->sub, "h");
                test_assert(w == &toks[40]);
                test_assert(h == &toks[42]);
            }
        }}
    }

    test_section("query_number")
    {
        struct json_token toks[128];
        json_number num;
        int ret;
        int i = 0;

        const char buf[] =
        "{\"map\":{"
            "\"entity\":["
                "{\"position\": {\"x\":1, \"y\":1}, \"size\":{\"w\":1,\"h\":1}},"
                "{\"position\": {\"x\":2, \"y\":2}, \"size\":{\"w\":2,\"h\":2}},"
                "{\"position\": {\"x\":3, \"y\":3}, \"size\":{\"w\":3,\"h\":3}},"
                "{\"position\": {\"x\":4, \"y\":4}, \"size\":{\"w\":4,\"h\":4}},"
                "{\"position\": {\"x\":5, \"y\":5}, \"size\":{\"w\":5,\"h\":5}}"
            "]"
        "}}";

        memset(toks, 0,  sizeof(toks));
        {struct json_parser p = {0};
        p.toks = toks; p.cap = 128;
        json_load(&p, buf, sizeof(buf));
        test_assert(p.err == JSON_OK);

        if (p.err == JSON_OK) {
            for (i = 0; i < 5; ++i) {
                char path[32];
                sprintf(path, "map.entity[%d].position.x", i);
                ret = json_query_number(&num, toks, p.cnt, path);
                test_assert(ret == JSON_NUMBER);
                test_assert(num == (json_number)(i + 1));

                sprintf(path, "map.entity[%d].position.y", i);
                ret = json_query_number(&num, toks, p.cnt, path);
                test_assert(ret == JSON_NUMBER);
                test_assert(num == (json_number)(i + 1));

                sprintf(path, "map.entity[%d].size.w", i);
                ret = json_query_number(&num, toks, p.cnt, path);
                test_assert(ret == JSON_NUMBER);
                test_assert(num == (json_number)(i + 1));

                sprintf(path, "map.entity[%d].size.h", i);
                ret = json_query_number(&num, toks, p.cnt, path);
                test_assert(ret == JSON_NUMBER);
                test_assert(num == (json_number)(i + 1));
            }
            test_assert(json_query_number(&num, toks, p.cnt, "map.test") == JSON_NONE);
            test_assert(json_query_number(&num, toks, p.cnt, "map.entity") == JSON_ARRAY);
        }}
    }

    test_section("query_string")
    {
        struct json_token toks[128];
        char buffer[256];
        int size;

        const char buf[] = "{\"b\": {\"a\": {\"b\":5}, \"b\":[1,2,3,4],"
            "\"c\":\"test\", \"d\":true, \"e\":false, \"f\":null, \"g\":10},"
            "\"a\": [{\"b\":5}, [1,2,3,4], \"test\", true, false, null, 10]}";

        memset(toks, 0,  sizeof(toks));
        {struct json_parser p = {0};
        p.toks = toks; p.cap = 128;
        json_load(&p, buf, sizeof(buf));
        test_assert(p.err == JSON_OK);

        if (p.err == JSON_OK) {
            test_assert(json_query_string(buffer, 256, &size, toks, p.cnt, "b.c")==JSON_STRING);
            test_assert(!strcmp(buffer, "test"));
            test_assert(json_query_string(buffer, 256, &size, toks, p.cnt, "a[2]")==JSON_STRING);
            test_assert(!strcmp(buffer, "test"));
            test_assert(json_query_string(buffer, 256, &size, toks, p.cnt, "a[0]")==JSON_OBJECT);
            test_assert(json_query_string(buffer, 256, &size, toks, p.cnt, "b.d")==JSON_TRUE);
            test_assert(json_query_string(buffer, 256, &size, toks, p.cnt, "b.h")==JSON_NONE);
        }}
    }

    test_section("query_type")
    {
        struct json_token toks[128];
        const char buf[] = "{\"b\": {\"a\": {\"b\":5}, \"b\":[1,2,3,4],"
            "\"c\":\"test\", \"d\":true, \"e\":false, \"f\":null, \"g\":10},"
            "\"a\": [{\"b\":5}, [1,2,3,4], \"test\", true, false, null, 10]}";

        memset(toks, 0,  sizeof(toks));
        {struct json_parser p = {0};
        p.toks = toks; p.cap = 128;
        json_load(&p, buf, sizeof(buf));
        test_assert(p.err == JSON_OK);

        if (p.err == JSON_OK) {
            test_assert(json_query_type(toks, p.cnt, "b") == JSON_OBJECT);
            test_assert(json_query_type(toks, p.cnt, "b.b") == JSON_ARRAY);
            test_assert(json_query_type(toks, p.cnt, "b.b[0]") == JSON_NUMBER);
            test_assert(json_query_type(toks, p.cnt, "b.c") == JSON_STRING);
            test_assert(json_query_type(toks, p.cnt, "b.d") == JSON_TRUE);
            test_assert(json_query_type(toks, p.cnt, "b.e") == JSON_FALSE);
            test_assert(json_query_type(toks, p.cnt, "b.f") == JSON_NULL);
        }}
    }
    test_section("test_case")
    {
        struct json_token toks[128];
        const char buf[] = "{\"value\": [0.500000, -0.012345, 1.0000]}";

        memset(toks, 0,  sizeof(toks));
        {struct json_parser p = {0};
        p.toks = toks; p.cap = 128;
        json_load(&p, buf, sizeof(buf));
        test_assert(p.err == JSON_OK);

        if (p.err == JSON_OK) {
            json_number val;
            test_assert(json_query_type(toks, p.cnt, "value[1]") == JSON_NUMBER);
            json_query_number(&val, toks, p.cnt, "value[1]");
            test_assert(fabs(val - (-0.012345)) < 0.00000001);
        }}
    }
    test_section("array_iteration")
    {
        struct json_token toks[256];
        struct json_token *a = 0;
        json_number num;
        int ret;
        int i = 0;

        const char buf[] =
        "{\"map\":{"
            "\"entity\":["
                "{\"position\": {\"x\":1, \"y\":1}, \"size\":{\"w\":1,\"h\":1}},"
                "{\"position\": {\"x\":2, \"y\":2}, \"size\":{\"w\":2,\"h\":2}},"
                "{\"position\": {\"x\":3, \"y\":3}, \"size\":{\"w\":3,\"h\":3}},"
                "{\"position\": {\"x\":4, \"y\":4}, \"size\":{\"w\":4,\"h\":4}},"
                "{\"position\": {\"x\":5, \"y\":5}, \"size\":{\"w\":5,\"h\":5}}"
            "]"
        "}}";

        memset(toks, 0,  sizeof(toks));
        {struct json_parser p = {0};
        p.toks = toks; p.cap = 256;
        json_load(&p, buf, sizeof(buf));
        test_assert(p.err == JSON_OK);

        if (p.err == JSON_OK) {
            a = json_query(toks, p.cnt, "map.entity");
            test_assert(a != 0);
            test_assert(a->type == JSON_ARRAY);

            /* iterate over each array element */
            {struct json_token *ent = json_array_begin(a);
            for (i = 0; i < a->children && ent; ++i) {
                /* position */
                struct json_token *pos = json_query(ent, ent->sub, "position");
                ret = json_query_number(&num, pos, pos->sub, "x");
                test_assert(ret == JSON_NUMBER);
                test_assert(num == (json_number)(i + 1));

                ret = json_query_number(&num, pos, pos->sub, "y");
                test_assert(ret == JSON_NUMBER);
                test_assert(num == (json_number)(i + 1));

                /* size */
                {struct json_token *size = json_query(ent, ent->sub, "size");
                ret = json_query_number(&num, size, size->sub, "w");
                test_assert(ret == JSON_NUMBER);
                test_assert(num == (json_number)(i + 1));

                ret = json_query_number(&num, size, size->sub, "h");
                test_assert(ret == JSON_NUMBER);
                test_assert(num == (json_number)(i + 1));
                ent = json_array_next(ent);}
            }}
        }}
    }
    test_section("root_iteration")
    {
        int ret;
        struct json_token toks[256];
        const char buf[] = "{\"a\"=5,\"b\"=true,\"c\"=false}";

        memset(toks, 0,  sizeof(toks));
        {struct json_parser p = {0};
        p.toks = toks; p.cap = 256;
        json_load(&p, buf, sizeof(buf));
        test_assert(p.err == JSON_OK);

        if (p.err == JSON_OK) {
            json_number num;

            /* iterate over each root object element */
            {struct json_token *elm = toks;
            while (elm < toks + p.cnt) {
                if (json_cmp(&elm[0], "a") == 0) {
                    ret = json_convert(&num, &elm[1]);
                    test_assert(ret == JSON_NUMBER);
                    test_assert(num == 5.0f);
                } else if (json_cmp(&elm[0], "b") == 0)
                    test_assert(elm[1].type == JSON_TRUE);
                else if (json_cmp(&elm[0], "c") == 0)
                    test_assert(elm[1].type == JSON_FALSE);
                elm = json_obj_next(elm);
            }}
        }}
    }
    test_section("object_iteration")
    {
        int ret, i = 0;
        struct json_token toks[256];
        const char buf[] = "{\"map\":{\"a\"=5,\"b\"=true,\"c\"=false}}";

        memset(toks, 0,  sizeof(toks));
        {struct json_parser p = {0};
        p.toks = toks; p.cap = 256;
        json_load(&p, buf, sizeof(buf));
        test_assert(p.err == JSON_OK);

        if (p.err == JSON_OK) {
            json_number num;
            struct json_token *m = json_query(toks, p.cnt, "map");
            test_assert(m != 0);
            test_assert(m->type == JSON_OBJECT);

            /* iterate over each map element */
            {struct json_token *elm = json_obj_begin(m);
            for (i = 0; i < m->children && elm; ++i) {
                if (json_cmp(&elm[0], "a") == 0) {
                    ret = json_convert(&num, &elm[1]);
                    test_assert(ret == JSON_NUMBER);
                    test_assert(num == 5.0f);
                } else if (json_cmp(&elm[0], "b") == 0)
                    test_assert(elm[1].type == JSON_TRUE);
                else if (json_cmp(&elm[0], "c") == 0)
                    test_assert(elm[1].type == JSON_FALSE);
                elm = json_obj_next(elm);
            }}
        }}

    }
    test_result();
    return fail_count;
}
int main(void)
{
    return run_test();
}

