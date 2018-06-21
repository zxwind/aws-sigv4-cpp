#include "awssigv4.h"

#include <cctype>

namespace aws_sigv4 {

    // Helper function for trim string
    // trim from start
    static inline std::string &ltrim(std::string &s) {
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](int c) {
            return !std::isspace(c);
        }));
        return s;
    }

    // trim from end
    static inline std::string &rtrim(std::string &s) {
        s.erase(std::find_if(s.rbegin(), s.rend(), [](int c) {
            return !std::isspace(c);
        }).base(), s.end());
        return s;
    }

    // trim from both ends
    static inline std::string &trim(std::string &s) {
            return ltrim(rtrim(s));
    }

    Signature::Signature(
        const std::string service,
        const std::string host,
        const std::string region,
        const std::string secret_key,
        const std::string access_key,
        const time_t sig_time
    )
    {
        m_service = service;
        m_host = host;
        m_region = region;
        m_secret_key = secret_key;
        m_access_key = access_key;

        //
        // Create a date for headers and the credential string
        struct tm  *tstruct = gmtime(&sig_time);
        strftime(m_amzdate, sizeof(m_amzdate), "%Y%m%dT%H%M%SZ", tstruct);
        strftime(m_datestamp, sizeof(m_datestamp), "%Y%m%d", tstruct);
    };

    void Signature::hashSha256(const std::string str, unsigned char outputBuffer[SHA256_DIGEST_LENGTH])
    {
        char *c_string = new char [str.length()+1];

        std::strcpy(c_string, str.c_str());        

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, c_string, std::strlen(c_string));
        SHA256_Final(hash, &sha256);

        for (int i=0;i<SHA256_DIGEST_LENGTH;i++) {
            outputBuffer[i] = hash[i];
        }

        delete[] c_string;
    }

    const std::string Signature::hexlify(const unsigned char* digest) {

        char outputBuffer[65];

        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            sprintf(outputBuffer + (i * 2), "%02x", digest[i]);
        }
        outputBuffer[64] = 0;

        return std::string(outputBuffer);

    }

    // equals to hashlib.sha256(str).hexdigest()
    const std::string Signature::sha256Base16(const std::string str) {
        unsigned char hashOut[SHA256_DIGEST_LENGTH];
        this->hashSha256(str,hashOut);

        return this->hexlify(hashOut);
    }

    // equals to  hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()
    const std::string Signature::sign(const std::string key, const std::string msg)
    {
        unsigned char *c_key = new unsigned char[key.length() + 1];
        memcpy(c_key, (unsigned char *)key.data(), key.length());

        unsigned char *c_msg = new unsigned char[msg.length() + 1];
        memcpy(c_msg, (unsigned char *)msg.data(), msg.length());

        unsigned char * digest = HMAC(EVP_sha256(), (unsigned char*)c_key, key.length(), c_msg, msg.length(), NULL, NULL); 

        delete[] c_key;
        delete[] c_msg;

        std::string signed_str = std::string((char *)digest, 32);
        
        return signed_str;
    }

    const std::string Signature::getSignatureKey()
    {
        std::string kDate = sign("AWS4" + m_secret_key, m_datestamp);
        std::string kRegion = sign(kDate, m_region);
        std::string kService = sign(kRegion, m_service);
        std::string kSigning = sign(kService, "aws4_request");
        return kSigning;
    }

    std::map<std::string, std::vector<std::string> > Signature::mergeHeaders(
        std::map<std::string, std::vector<std::string> > canonical_header_map)
    {
        std::map<std::string, std::vector<std::string> > merge_header_map;
        std::map<std::string, std::vector<std::string> >::iterator search_it;

        for (std::map<std::string, std::vector<std::string> >::iterator it=canonical_header_map.begin(); it != canonical_header_map.end(); it++)
        {
            std::string header_key = it->first;
            std::transform(header_key.begin(), header_key.end(), header_key.begin(), ::tolower);
            header_key = trim(header_key);

            search_it = merge_header_map.find(header_key);

            if (search_it == merge_header_map.end())
            {
                merge_header_map[header_key];
            }
            for (std::vector<std::string>::iterator lit=it->second.begin(); lit != it->second.end(); lit++)
            {
                std::string header_value = *lit;
                header_value = trim(header_value);
                merge_header_map[header_key].push_back(header_value);
            }
        }

        for (std::map<std::string, std::vector<std::string> >::iterator it=merge_header_map.begin(); it != merge_header_map.end(); it++)
        {
            std::sort(it->second.begin(), it->second.end());  
        }

        return merge_header_map;
    }

    std::string Signature::canonicalHeaderStr(
        std::map<std::string, std::vector<std::string> > canonical_header_map)
    {
        std::string canonical_headers = "";
        for (std::map<std::string, std::vector<std::string> >::iterator it=canonical_header_map.begin(); it != canonical_header_map.end(); it++)
        {
            canonical_headers += it->first + ":";
            for(std::vector<std::string>::iterator yit=it->second.begin(); yit != it->second.end();)
            {
                canonical_headers += *yit;
                
                if(++yit != it->second.end())
                    canonical_headers += ",";
            }
            canonical_headers += "\n";
        }

        return canonical_headers;
    }
    
    std::string Signature::signedHeaderStr(
        std::map<std::string, std::vector<std::string> > canonical_header_map)
    {
        std::string signed_header = ""; 
        for (std::map<std::string, std::vector<std::string> >::iterator it=canonical_header_map.begin(); it != canonical_header_map.end();)
        {
            signed_header += it->first;

            if(++it != canonical_header_map.end())
                signed_header += ";";
        }
        return signed_header;
    }

    std::string Signature::createCanonicalQueryString(std::string query_string)
    {
        std::map<std::string, std::vector<std::string> > query_map;

        std::stringstream qss(query_string);
        std::string query_pair;

        while(std::getline(qss, query_pair, '&'))
        {
            std::size_t epos = query_pair.find("=");
            std::string query_key, query_val;

            if (epos != std::string::npos)
            {
                query_key = query_pair.substr(0, epos);
                query_val = query_pair.substr(epos+1);
            }

            std::map<std::string, std::vector<std::string> >::iterator search_it = query_map.find(query_key);

            if (search_it == query_map.end())
            {
                query_map[query_key];
            }

            query_map[query_key].push_back(query_val);
        }

        for (std::map<std::string, std::vector<std::string> >::iterator it=query_map.begin(); it != query_map.end(); it++)
        {
            std::sort(it->second.begin(), it->second.end());  
        }

        std::string canonical_query_string = "";
        for (std::map<std::string, std::vector<std::string> >::iterator it=query_map.begin(); it != query_map.end();)
        {
            for(std::vector<std::string>::iterator yit=it->second.begin(); yit != it->second.end();)
            {
                canonical_query_string += it->first + "=" + *yit;
                
                if(++yit != it->second.end())
                    canonical_query_string += "&";
            }
                
            if(++it != query_map.end())
                canonical_query_string += "&";
        }

        return canonical_query_string;

    }

    std::string Signature::createCanonicalRequest(
        const std::string method,
        const std::string canonical_uri,
        const std::string querystring, 
        std::map<std::string, std::vector<std::string> > canonical_header_map,
        const std::string payload
    )
    {

        // Step 1: create canonical request
        // http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

        // Step 1.1 define the verb (GET, POST, etc.)
        // passed in as argument

        // Step 1.2: Create canonical URI--the part of the URI from domain to query 
        // string (use '/' if no path)
        // passed in as argument

        // Step 1.3: Create the canonical query string. In this example (a GET request),
        // request parameters are in the query string. Query string values must
        // be URL-encoded (space=%20). The parameters must be sorted by name.
        // For this example, the query string is pre-formatted in the request_parameters variable.
        // passed in as argument

        // Step 1.4: Create the canonical headers and signed headers. Header names
        // and value must be trimmed and lowercase, and sorted in ASCII order.
        // Note that there is a trailing \n.

        std::map<std::string, std::vector<std::string> > merged_headers = mergeHeaders(canonical_header_map);

        std::string canonical_headers = canonicalHeaderStr(merged_headers);

        // Step 1.5: Create the list of signed headers. This lists the headers
        // in the canonical_headers list, delimited with ";" and in alpha order.
        // Note: The request can include any headers; canonical_headers and
        // signed_headers lists those that you want to be included in the 
        //hash of the request. "Host" and "x-amz-date" are always required.
        m_signed_headers = signedHeaderStr(merged_headers);

        // Step 1.6: Create payload hash (hash of the request body content). For GET
        // requests, the payload is an empty string ("").
        std::string payload_hash = sha256Base16(payload);

        // Step 1.7: Combine elements to create create canonical request

        // generate canonical query string
        std::string canonical_querystring = createCanonicalQueryString(querystring);

        std::string canonical_request = method + "\n" + canonical_uri + "\n" + canonical_querystring + "\n" + canonical_headers + "\n" + m_signed_headers + "\n" + payload_hash;
    
        return canonical_request;
    }

    
    std::string Signature::createStringToSign(std::string canonical_request)
    {
        // Step 2: CREATE THE STRING TO SIGN
        // http://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
        // Match the algorithm to the hashing algorithm you use, either SHA-1 or
        // SHA-256 (recommended)

        std::string algorithm = "AWS4-HMAC-SHA256";
        std::string credential_scope = std::string(m_datestamp) + "/" + m_region + "/" + m_service + "/" + "aws4_request";
        std::string string_to_sign = algorithm + '\n' +  m_amzdate + '\n' +  credential_scope + '\n' +  sha256Base16(canonical_request);

        return string_to_sign;
    }
    
    std::string Signature::createSignature(std::string string_to_sign)
    {
        // step 3: CALCULATE THE SIGNATURE
        // http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
        // Create the signing key using the function defined above.
        std::string signing_key = this->getSignatureKey();

        // Sign the string_to_sign using the signing_key
        std::string signature_str = sign(signing_key, string_to_sign);

        unsigned char *signature_data = new unsigned char[signature_str.length() + 1];
        memcpy(signature_data, (unsigned char *)signature_str.data(), signature_str.length());

        std::string signature = hexlify(signature_data);

        delete[] signature_data;
        
        return signature;
    }
    
    
    std::string Signature::createAuthorizationHeader(std::string signature)
    {
            
        std::string algorithm = "AWS4-HMAC-SHA256";
        std::string credential_scope = std::string(m_datestamp) + "/" + m_region + "/" + m_service + "/" + "aws4_request";

        return algorithm + " " + "Credential=" + m_access_key + "/" + credential_scope + ", " +  "SignedHeaders=" + m_signed_headers + ", " + "Signature=" + signature;
    }

}
