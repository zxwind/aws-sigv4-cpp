// SIgn aws request with v4 signature
// http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html

#include <iostream>
#include <string.h>
#include <sstream> 
#include <cstring>
#include <stdio.h>
#include <stdlib.h>
#include <ctime>
#include <map>
#include <vector>
#include <algorithm>
#include "openssl/sha.h"
#include "openssl/hmac.h"

namespace aws_sigv4 {

    class Signature
    {
        private:
            std::string m_secret_key, m_access_key, m_service, m_host, m_region, m_signed_headers;
            
            char m_amzdate[20];
            char m_datestamp[20];

            const std::string getSignatureKey();

            void hashSha256(const std::string str, unsigned char outputBuffer[SHA256_DIGEST_LENGTH]);

            // digest to hexdiges
            const std::string hexlify(const unsigned char* digest);

            // equals to hashlib.sha256(str).hexdigest()
            const std::string sha256Base16(const std::string str);

            // equals to  hmac.new(key, msg, hashlib.sha256).digest()
            const std::string sign(const std::string key, const std::string msg);

            std::map<std::string, std::vector<std::string> > mergeHeaders(
                std::map<std::string, std::vector<std::string> > canonical_header_map        
            );
            std::string canonicalHeaderStr(std::map<std::string, std::vector<std::string> > canonical_header_map);
            std::string signedHeaderStr(std::map<std::string, std::vector<std::string> > canonical_header_map);

            std::string createCanonicalQueryString(std::string query_string);

        public:
            Signature(
                const std::string service,
                const std::string host,
                const std::string region,
                const std::string secret_key,
                const std::string access_key,
                const time_t sig_time=time(0)
            );

            // Step 1: creaate a canonical request
            std::string createCanonicalRequest(
                const std::string method,
                const std::string canonical_uri,
                const std::string querystring, 
                std::map<std::string, std::vector<std::string> > canonical_header_map,
                const std::string payload
            );

            // Step 2: CREATE THE STRING TO SIGN
            std::string createStringToSign(std::string canonical_request);

            // step 3: CALCULATE THE SIGNATURE
            std::string createSignature(std::string string_to_sign);

            // Step 4.1: CREATE Authorization header
            // This method assuemd to be called after previous step
            // So It can get credential scope and signed headers
            std::string createAuthorizationHeader(std::string signature);
    };

}
