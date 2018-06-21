#include "gtest/gtest.h"
#include "fstream"
#include <vector>
#include <map>
#include <algorithm> 
#include <functional> 
#include <cctype>
#include <locale>

#include "awssigv4.h"

std::string GetWholeFile(std::string file_name)
{
    std::ifstream whole_file(file_name.c_str(), std::ios::in|std::ios::binary);
    std::stringstream whole_file_stream;
    whole_file_stream << whole_file.rdbuf();
    std::string whole_file_str = whole_file_stream.str();

    std::string::size_type rpos = 0;
    while ( ( rpos = whole_file_str.find ("\r", rpos) ) != std::string::npos )
    {
        whole_file_str.erase ( rpos, 1);
    }

    return whole_file_str;
}


std::string GetCreateCanonicalRequest(std::string req_file)
{

    std::ifstream reqfile(req_file.c_str(), std::ios::in|std::ios::binary);

    std::string line;
    std::string method, canonical_uri, protocal, payload;
    std::map<std::string, std::vector<std::string> > header_map;
    if (reqfile.is_open())
    {
        int line_count=0;
        while (getline(reqfile, line))
        {
            std::string::size_type rpos = 0;
            while ( ( rpos = line.find ("\r", rpos) ) != std::string::npos )
            {
                line.erase ( rpos, 1);
            }

            if (line_count == 0)
            {
                std::stringstream linestream(line);
                linestream >> method >> canonical_uri >> protocal;
            }
            else
            {
                 std::size_t pos = line.find(":");
                 if (pos != std::string::npos)
                {
                    std::string header, value;
                    header = line.substr(0, pos);
                    value = line.substr(pos+1);

                    if (header_map.find(header) == header_map.end())
                    {
                        header_map[header];
                    }

                    header_map[header].push_back(value);
                }
                else
                {
                 std::size_t epos = line.find("=");
                 if (epos != std::string::npos)
                     payload += line;
                }
            }

            line_count++;
        }
    }

    aws_sigv4::Signature signature(
        "host",
        "host.foo.com",
        "us-east-1",
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "AKIDEXAMPLE"
    );

    std::size_t qpos = canonical_uri.find("?");
    std::string canonical_base_uri = canonical_uri;
    std::string query_string = "";

    if (qpos != std::string::npos)
    {
        canonical_base_uri = canonical_uri.substr(0,qpos);
        query_string = canonical_uri.substr(qpos+1);
    }
    return signature.createCanonicalRequest(method, canonical_base_uri, query_string, header_map, payload);
}


std::string GetCreateStringToSign(std::string creq_file)
{

    std::string canonical_request = GetWholeFile(creq_file);

    time_t rawtime;
    time ( &rawtime );
    struct tm * timeinfo = gmtime ( &rawtime );
    timeinfo->tm_year = 2011 - 1900;
    timeinfo->tm_mon = 9 - 1;
    timeinfo->tm_mday = 9;
    timeinfo->tm_hour = 23;
    timeinfo->tm_min = 36;
    timeinfo->tm_sec = 0;

    time_t sig_time = mktime( timeinfo ) - timezone;

    aws_sigv4::Signature signature(
        "host",
        "host.foo.com",
        "us-east-1",
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "AKIDEXAMPLE",
        sig_time
    );

    return signature.createStringToSign(canonical_request);
}


std::string GetAuthorizationHeader(std::string req_file, std::string sts_file)
{
    std::ifstream reqfile(req_file.c_str(), std::ios::in|std::ios::binary);

    std::string line;
    std::string method, canonical_uri, protocal, payload;
    std::map<std::string, std::vector<std::string> > header_map;
    if (reqfile.is_open())
    {
        int line_count=0;
        while (getline(reqfile, line))
        {
            std::string::size_type rpos = 0;
            while ( ( rpos = line.find ("\r", rpos) ) != std::string::npos )
            {
                line.erase ( rpos, 1);
            }

            if (line_count == 0)
            {
                std::stringstream linestream(line);
                linestream >> method >> canonical_uri >> protocal;
            }
            else
            {
                 std::size_t pos = line.find(":");
                 if (pos != std::string::npos)
                {
                    std::string header, value;
                    header = line.substr(0, pos);
                    value = line.substr(pos+1);

                    if (header_map.find(header) == header_map.end())
                    {
                        header_map[header];
                    }

                    header_map[header].push_back(value);
                }
                else
                {
                 std::size_t epos = line.find("=");
                 if (epos != std::string::npos)
                     payload += line;
                }
            }

            line_count++;
        }
    }

    time_t rawtime;
    time ( &rawtime );
    struct tm * timeinfo = gmtime ( &rawtime );
    timeinfo->tm_year = 2011 - 1900;
    timeinfo->tm_mon = 9 - 1;
    timeinfo->tm_mday = 9;
    timeinfo->tm_hour = 23;
    timeinfo->tm_min = 36;
    timeinfo->tm_sec = 0;

    time_t sig_time = mktime( timeinfo ) - timezone;

    aws_sigv4::Signature signature(
        "host",
        "host.foo.com",
        "us-east-1",
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "AKIDEXAMPLE",
        sig_time
    );

    std::size_t qpos = canonical_uri.find("?");
    std::string canonical_base_uri = canonical_uri;
    std::string query_string = "";

    if (qpos != std::string::npos)
    {
        canonical_base_uri = canonical_uri.substr(0,qpos);
        query_string = canonical_uri.substr(qpos+1);
    }
    
    signature.createCanonicalRequest(method, canonical_base_uri, query_string, header_map, payload);

    std::string string_to_sign = GetWholeFile(sts_file.c_str());

    std::string signature_str = signature.createSignature(string_to_sign);

    return signature.createAuthorizationHeader(signature_str);
}

// Task 1: Create a Canonical Request for Signature Version 4

TEST(createCanonicalRequest, get_header_key_duplicate)
{
    std::string canonical_request = GetCreateCanonicalRequest("aws4_testsuite/get-header-key-duplicate.req");

    EXPECT_EQ(canonical_request, GetWholeFile("aws4_testsuite/get-header-key-duplicate.creq"));
}

TEST(createCanonicalRequest, get_header_value_order)
{
    std::string canonical_request = GetCreateCanonicalRequest("aws4_testsuite/get-header-value-order.req");

    EXPECT_EQ(canonical_request, GetWholeFile("aws4_testsuite/get-header-value-order.creq"));
}


TEST(createCanonicalRequest, get_header_value_trim)
{
    std::string canonical_request = GetCreateCanonicalRequest("aws4_testsuite/get-header-value-trim.req");

    EXPECT_EQ(canonical_request, GetWholeFile("aws4_testsuite/get-header-value-trim.creq"));
}


TEST(createCanonicalRequest, get_vanilla)
{
    std::string canonical_request = GetCreateCanonicalRequest("aws4_testsuite/get-vanilla.req");

    EXPECT_EQ(canonical_request, GetWholeFile("aws4_testsuite/get-vanilla.creq"));
}


TEST(createCanonicalRequest, get_vanilla_empty_query_key)
{
    std::string canonical_request = GetCreateCanonicalRequest("aws4_testsuite/get-vanilla-empty-query-key.req");

    EXPECT_EQ(canonical_request, GetWholeFile("aws4_testsuite/get-vanilla-empty-query-key.creq"));
}

TEST(createCanonicalRequest, get_vanilla_query)
{
    std::string canonical_request = GetCreateCanonicalRequest("aws4_testsuite/get-vanilla-query.req");

    EXPECT_EQ(canonical_request, GetWholeFile("aws4_testsuite/get-vanilla-query.creq"));
}


TEST(createCanonicalRequest, get_vanilla_query_order_key)
{
    std::string canonical_request = GetCreateCanonicalRequest("aws4_testsuite/get-vanilla-query-order-key.req");

    EXPECT_EQ(canonical_request, GetWholeFile("aws4_testsuite/get-vanilla-query-order-key.creq"));
}


TEST(createCanonicalRequest, get_vanilla_query_order_key_case)
{
    std::string canonical_request = GetCreateCanonicalRequest("aws4_testsuite/get-vanilla-query-order-key-case.req");

    EXPECT_EQ(canonical_request, GetWholeFile("aws4_testsuite/get-vanilla-query-order-key-case.creq"));
}


TEST(createCanonicalRequest, get_vanilla_query_order_value)
{
    std::string canonical_request = GetCreateCanonicalRequest("aws4_testsuite/get-vanilla-query-order-value.req");

    EXPECT_EQ(canonical_request, GetWholeFile("aws4_testsuite/get-vanilla-query-order-value.creq"));
}


TEST(createCanonicalRequest,get_vanilla_query_unreserved)
{
    std::string canonical_request = GetCreateCanonicalRequest("aws4_testsuite/get-vanilla-query-unreserved.req");

    EXPECT_EQ(canonical_request, GetWholeFile("aws4_testsuite/get-vanilla-query-unreserved.creq"));
}


TEST(createCanonicalRequest,post_header_key_case)
{
    std::string canonical_request = GetCreateCanonicalRequest("aws4_testsuite/post-header-key-case.req");

    EXPECT_EQ(canonical_request, GetWholeFile("aws4_testsuite/post-header-key-case.creq"));
}


TEST(createCanonicalRequest,post_header_key_sort)
{
    std::string canonical_request = GetCreateCanonicalRequest("aws4_testsuite/post-header-key-sort.req");

    EXPECT_EQ(canonical_request, GetWholeFile("aws4_testsuite/post-header-key-sort.creq"));
}


TEST(createCanonicalRequest,post_header_value_case)
{
    std::string canonical_request = GetCreateCanonicalRequest("aws4_testsuite/post-header-value-case.req");

    EXPECT_EQ(canonical_request, GetWholeFile("aws4_testsuite/post-header-value-case.creq"));
}


TEST(createCanonicalRequest,post_vanilla)
{
    std::string canonical_request = GetCreateCanonicalRequest("aws4_testsuite/post-vanilla.req");

    EXPECT_EQ(canonical_request, GetWholeFile("aws4_testsuite/post-vanilla.creq"));
}


TEST(createCanonicalRequest,post_vanilla_empty_query_value)
{
    std::string canonical_request = GetCreateCanonicalRequest("aws4_testsuite/post-vanilla-empty-query-value.req");

    EXPECT_EQ(canonical_request, GetWholeFile("aws4_testsuite/post-vanilla-empty-query-value.creq"));
}


TEST(createCanonicalRequest,post_vanilla_query)
{
    std::string canonical_request = GetCreateCanonicalRequest("aws4_testsuite/post-vanilla-query.req");

    EXPECT_EQ(canonical_request, GetWholeFile("aws4_testsuite/post-vanilla-query.creq"));
}


TEST(createCanonicalRequest,post_x_www_form_urlencoded)
{
    std::string canonical_request = GetCreateCanonicalRequest("aws4_testsuite/post-x-www-form-urlencoded.req");

    EXPECT_EQ(canonical_request, GetWholeFile("aws4_testsuite/post-x-www-form-urlencoded.creq"));
}


TEST(createCanonicalRequest,post_x_www_form_urlencoded_parameters)
{
    std::string canonical_request = GetCreateCanonicalRequest("aws4_testsuite/post-x-www-form-urlencoded-parameters.req");

    EXPECT_EQ(canonical_request, GetWholeFile("aws4_testsuite/post-x-www-form-urlencoded-parameters.creq"));
}

// Task 2: Create a String to Sign for Signature Version 4
TEST(createStringToSign, get_header_key_duplicate)
{
    std::string string_to_sign = GetCreateStringToSign("aws4_testsuite/get-header-key-duplicate.creq");

    EXPECT_EQ(string_to_sign, GetWholeFile("aws4_testsuite/get-header-key-duplicate.sts"));
}


TEST(createStringToSign, get_header_value_order)
{
    std::string string_to_sign = GetCreateStringToSign("aws4_testsuite/get-header-value-order.creq");

    EXPECT_EQ(string_to_sign, GetWholeFile("aws4_testsuite/get-header-value-order.sts"));
}


TEST(createStringToSign, get_header_value_trim)
{
    std::string string_to_sign = GetCreateStringToSign("aws4_testsuite/get-header-value-trim.creq");

    EXPECT_EQ(string_to_sign, GetWholeFile("aws4_testsuite/get-header-value-trim.sts"));
}


TEST(createStringToSign, get_relative)
{
    std::string string_to_sign = GetCreateStringToSign("aws4_testsuite/get-relative.creq");

    EXPECT_EQ(string_to_sign, GetWholeFile("aws4_testsuite/get-relative.sts"));
}


TEST(createStringToSign, get_relative_relative)
{
    std::string string_to_sign = GetCreateStringToSign("aws4_testsuite/get-relative-relative.creq");

    EXPECT_EQ(string_to_sign, GetWholeFile("aws4_testsuite/get-relative-relative.sts"));
}


TEST(createStringToSign, get_slash)
{
    std::string string_to_sign = GetCreateStringToSign("aws4_testsuite/get-slash.creq");

    EXPECT_EQ(string_to_sign, GetWholeFile("aws4_testsuite/get-slash.sts"));
}


TEST(createStringToSign, get_slash_dot_slash)
{
    std::string string_to_sign = GetCreateStringToSign("aws4_testsuite/get-slash-dot-slash.creq");

    EXPECT_EQ(string_to_sign, GetWholeFile("aws4_testsuite/get-slash-dot-slash.sts"));
}


TEST(createStringToSign, get_slashes)
{
    std::string string_to_sign = GetCreateStringToSign("aws4_testsuite/get-slashes.creq");

    EXPECT_EQ(string_to_sign, GetWholeFile("aws4_testsuite/get-slashes.sts"));
}


TEST(createStringToSign, get_slash_pointless_dot)
{
    std::string string_to_sign = GetCreateStringToSign("aws4_testsuite/get-slash-pointless-dot.creq");

    EXPECT_EQ(string_to_sign, GetWholeFile("aws4_testsuite/get-slash-pointless-dot.sts"));
}


TEST(createStringToSign, get_space)
{
    std::string string_to_sign = GetCreateStringToSign("aws4_testsuite/get-space.creq");

    EXPECT_EQ(string_to_sign, GetWholeFile("aws4_testsuite/get-space.sts"));
}


TEST(createStringToSign, get_unreserved)
{
    std::string string_to_sign = GetCreateStringToSign("aws4_testsuite/get-unreserved.creq");

    EXPECT_EQ(string_to_sign, GetWholeFile("aws4_testsuite/get-unreserved.sts"));
}


TEST(createStringToSign, get_utf8)
{
    std::string string_to_sign = GetCreateStringToSign("aws4_testsuite/get-utf8.creq");

    EXPECT_EQ(string_to_sign, GetWholeFile("aws4_testsuite/get-utf8.sts"));
}


TEST(createStringToSign, get_vanilla)
{
    std::string string_to_sign = GetCreateStringToSign("aws4_testsuite/get-vanilla.creq");

    EXPECT_EQ(string_to_sign, GetWholeFile("aws4_testsuite/get-vanilla.sts"));
}


TEST(createStringToSign, get_vanilla_empty_query_key)
{
    std::string string_to_sign = GetCreateStringToSign("aws4_testsuite/get-vanilla-empty-query-key.creq");

    EXPECT_EQ(string_to_sign, GetWholeFile("aws4_testsuite/get-vanilla-empty-query-key.sts"));
}


TEST(createStringToSign, get_vanilla_query)
{
    std::string string_to_sign = GetCreateStringToSign("aws4_testsuite/get-vanilla-query.creq");

    EXPECT_EQ(string_to_sign, GetWholeFile("aws4_testsuite/get-vanilla-query.sts"));
}


TEST(createStringToSign, get_vanilla_query_order_key)
{
    std::string string_to_sign = GetCreateStringToSign("aws4_testsuite/get-vanilla-query-order-key.creq");

    EXPECT_EQ(string_to_sign, GetWholeFile("aws4_testsuite/get-vanilla-query-order-key.sts"));
}


TEST(createStringToSign, get_vanilla_query_order_key_case)
{
    std::string string_to_sign = GetCreateStringToSign("aws4_testsuite/get-vanilla-query-order-key-case.creq");

    EXPECT_EQ(string_to_sign, GetWholeFile("aws4_testsuite/get-vanilla-query-order-key-case.sts"));
}


TEST(createStringToSign, get_vanilla_query_order_value)
{
    std::string string_to_sign = GetCreateStringToSign("aws4_testsuite/get-vanilla-query-order-value.creq");

    EXPECT_EQ(string_to_sign, GetWholeFile("aws4_testsuite/get-vanilla-query-order-value.sts"));
}


TEST(createStringToSign, get_vanilla_query_unreserved)
{
    std::string string_to_sign = GetCreateStringToSign("aws4_testsuite/get-vanilla-query-unreserved.creq");

    EXPECT_EQ(string_to_sign, GetWholeFile("aws4_testsuite/get-vanilla-query-unreserved.sts"));
}


TEST(createStringToSign, get_vanilla_ut8_query)
{
    std::string string_to_sign = GetCreateStringToSign("aws4_testsuite/get-vanilla-ut8-query.creq");

    EXPECT_EQ(string_to_sign, GetWholeFile("aws4_testsuite/get-vanilla-ut8-query.sts"));
}


TEST(createStringToSign, post_header_key_case)
{
    std::string string_to_sign = GetCreateStringToSign("aws4_testsuite/post-header-key-case.creq");

    EXPECT_EQ(string_to_sign, GetWholeFile("aws4_testsuite/post-header-key-case.sts"));
}


TEST(createStringToSign, post_header_key_sort)
{
    std::string string_to_sign = GetCreateStringToSign("aws4_testsuite/post-header-key-sort.creq");

    EXPECT_EQ(string_to_sign, GetWholeFile("aws4_testsuite/post-header-key-sort.sts"));
}


TEST(createStringToSign, post_header_value_case)
{
    std::string string_to_sign = GetCreateStringToSign("aws4_testsuite/post-header-value-case.creq");

    EXPECT_EQ(string_to_sign, GetWholeFile("aws4_testsuite/post-header-value-case.sts"));
}


TEST(createStringToSign, post_vanilla)
{
    std::string string_to_sign = GetCreateStringToSign("aws4_testsuite/post-vanilla.creq");

    EXPECT_EQ(string_to_sign, GetWholeFile("aws4_testsuite/post-vanilla.sts"));
}


TEST(createStringToSign, post_vanilla_empty_query_value)
{
    std::string string_to_sign = GetCreateStringToSign("aws4_testsuite/post-vanilla-empty-query-value.creq");

    EXPECT_EQ(string_to_sign, GetWholeFile("aws4_testsuite/post-vanilla-empty-query-value.sts"));
}


TEST(createStringToSign, post_vanilla_query)
{
    std::string string_to_sign = GetCreateStringToSign("aws4_testsuite/post-vanilla-query.creq");

    EXPECT_EQ(string_to_sign, GetWholeFile("aws4_testsuite/post-vanilla-query.sts"));
}


TEST(createStringToSign, post_vanilla_query_nonunreserved)
{
    std::string string_to_sign = GetCreateStringToSign("aws4_testsuite/post-vanilla-query-nonunreserved.creq");

    EXPECT_EQ(string_to_sign, GetWholeFile("aws4_testsuite/post-vanilla-query-nonunreserved.sts"));
}


TEST(createStringToSign, post_vanilla_query_space)
{
    std::string string_to_sign = GetCreateStringToSign("aws4_testsuite/post-vanilla-query-space.creq");

    EXPECT_EQ(string_to_sign, GetWholeFile("aws4_testsuite/post-vanilla-query-space.sts"));
}


TEST(createStringToSign, post_x_www_form_urlencoded)
{
    std::string string_to_sign = GetCreateStringToSign("aws4_testsuite/post-x-www-form-urlencoded.creq");

    EXPECT_EQ(string_to_sign, GetWholeFile("aws4_testsuite/post-x-www-form-urlencoded.sts"));
}


TEST(createStringToSign, post_x_www_form_urlencoded_parameters)
{
    std::string string_to_sign = GetCreateStringToSign("aws4_testsuite/post-x-www-form-urlencoded-parameters.creq");

    EXPECT_EQ(string_to_sign, GetWholeFile("aws4_testsuite/post-x-www-form-urlencoded-parameters.sts"));
}

// Task 3:  Calculate the AWS Signature Version 4

TEST(createAuthorizationHeader, get_header_key_duplicate)
{
    std::string authorization_header = GetAuthorizationHeader("aws4_testsuite/get-header-key-duplicate.req", "aws4_testsuite/get-header-key-duplicate.sts");

    EXPECT_EQ(authorization_header, GetWholeFile("aws4_testsuite/get-header-key-duplicate.authz"));
}

TEST(createAuthorizationHeader, get_header_value_order)
{
    std::string authorization_header = GetAuthorizationHeader("aws4_testsuite/get-header-value-order.req", "aws4_testsuite/get-header-value-order.sts");

    EXPECT_EQ(authorization_header, GetWholeFile("aws4_testsuite/get-header-value-order.authz"));
}


TEST(createAuthorizationHeader, get_header_value_trim)
{
    std::string authorization_header = GetAuthorizationHeader("aws4_testsuite/get-header-value-trim.req", "aws4_testsuite/get-header-value-trim.sts");

    EXPECT_EQ(authorization_header, GetWholeFile("aws4_testsuite/get-header-value-trim.authz"));
}


TEST(createAuthorizationHeader, get_vanilla)
{
    std::string authorization_header = GetAuthorizationHeader("aws4_testsuite/get-vanilla.req", "aws4_testsuite/get-vanilla.sts");

    EXPECT_EQ(authorization_header, GetWholeFile("aws4_testsuite/get-vanilla.authz"));
}


TEST(createAuthorizationHeader, get_vanilla_empty_query_key)
{
    std::string authorization_header = GetAuthorizationHeader("aws4_testsuite/get-vanilla-empty-query-key.req", "aws4_testsuite/get-vanilla-empty-query-key.sts");

    EXPECT_EQ(authorization_header, GetWholeFile("aws4_testsuite/get-vanilla-empty-query-key.authz"));
}


TEST(createAuthorizationHeader, get_vanilla_query)
{
    std::string authorization_header = GetAuthorizationHeader("aws4_testsuite/get-vanilla-query.req", "aws4_testsuite/get-vanilla-query.sts");

    EXPECT_EQ(authorization_header, GetWholeFile("aws4_testsuite/get-vanilla-query.authz"));
}


TEST(createAuthorizationHeader, get_vanilla_query_order_key)
{
    std::string authorization_header = GetAuthorizationHeader("aws4_testsuite/get-vanilla-query-order-key.req", "aws4_testsuite/get-vanilla-query-order-key.sts");

    EXPECT_EQ(authorization_header, GetWholeFile("aws4_testsuite/get-vanilla-query-order-key.authz"));
}


TEST(createAuthorizationHeader, get_vanilla_query_order_key_case)
{
    std::string authorization_header = GetAuthorizationHeader("aws4_testsuite/get-vanilla-query-order-key-case.req", "aws4_testsuite/get-vanilla-query-order-key-case.sts");

    EXPECT_EQ(authorization_header, GetWholeFile("aws4_testsuite/get-vanilla-query-order-key-case.authz"));
}


TEST(createAuthorizationHeader, get_vanilla_query_order_value)
{
    std::string authorization_header = GetAuthorizationHeader("aws4_testsuite/get-vanilla-query-order-value.req", "aws4_testsuite/get-vanilla-query-order-value.sts");

    EXPECT_EQ(authorization_header, GetWholeFile("aws4_testsuite/get-vanilla-query-order-value.authz"));
}


TEST(createAuthorizationHeader, get_vanilla_query_unreserved)
{
    std::string authorization_header = GetAuthorizationHeader("aws4_testsuite/get-vanilla-query-unreserved.req", "aws4_testsuite/get-vanilla-query-unreserved.sts");

    EXPECT_EQ(authorization_header, GetWholeFile("aws4_testsuite/get-vanilla-query-unreserved.authz"));
}


TEST(createAuthorizationHeader, post_header_key_case)
{
    std::string authorization_header = GetAuthorizationHeader("aws4_testsuite/post-header-key-case.req", "aws4_testsuite/post-header-key-case.sts");

    EXPECT_EQ(authorization_header, GetWholeFile("aws4_testsuite/post-header-key-case.authz"));
}


TEST(createAuthorizationHeader, post_header_key_sort)
{
    std::string authorization_header = GetAuthorizationHeader("aws4_testsuite/post-header-key-sort.req", "aws4_testsuite/post-header-key-sort.sts");

    EXPECT_EQ(authorization_header, GetWholeFile("aws4_testsuite/post-header-key-sort.authz"));
}


TEST(createAuthorizationHeader, post_header_value_case)
{
    std::string authorization_header = GetAuthorizationHeader("aws4_testsuite/post-header-value-case.req", "aws4_testsuite/post-header-value-case.sts");

    EXPECT_EQ(authorization_header, GetWholeFile("aws4_testsuite/post-header-value-case.authz"));
}


TEST(createAuthorizationHeader, post_vanilla)
{
    std::string authorization_header = GetAuthorizationHeader("aws4_testsuite/post-vanilla.req", "aws4_testsuite/post-vanilla.sts");

    EXPECT_EQ(authorization_header, GetWholeFile("aws4_testsuite/post-vanilla.authz"));
}


TEST(createAuthorizationHeader, post_vanilla_empty_query_value)
{
    std::string authorization_header = GetAuthorizationHeader("aws4_testsuite/post-vanilla-empty-query-value.req", "aws4_testsuite/post-vanilla-empty-query-value.sts");

    EXPECT_EQ(authorization_header, GetWholeFile("aws4_testsuite/post-vanilla-empty-query-value.authz"));
}


TEST(createAuthorizationHeader, post_vanilla_query)
{
    std::string authorization_header = GetAuthorizationHeader("aws4_testsuite/post-vanilla-query.req", "aws4_testsuite/post-vanilla-query.sts");

    EXPECT_EQ(authorization_header, GetWholeFile("aws4_testsuite/post-vanilla-query.authz"));
}


TEST(createAuthorizationHeader, post_x_www_form_urlencoded)
{
    std::string authorization_header = GetAuthorizationHeader("aws4_testsuite/post-x-www-form-urlencoded.req", "aws4_testsuite/post-x-www-form-urlencoded.sts");

    EXPECT_EQ(authorization_header, GetWholeFile("aws4_testsuite/post-x-www-form-urlencoded.authz"));
}


TEST(createAuthorizationHeader, post_x_www_form_urlencoded_parameters)
{
    std::string authorization_header = GetAuthorizationHeader("aws4_testsuite/post-x-www-form-urlencoded-parameters.req", "aws4_testsuite/post-x-www-form-urlencoded-parameters.sts");

    EXPECT_EQ(authorization_header, GetWholeFile("aws4_testsuite/post-x-www-form-urlencoded-parameters.authz"));
}
