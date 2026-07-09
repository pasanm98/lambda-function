const { S3Client, GetObjectCommand } = require("@aws-sdk/client-s3");
var zlib = require('zlib');
var https = require('https');
var crypto = require('crypto');
const s3 = new S3Client({ region: 'ap-southeast-1' });

var endpoint = process.env.ELASTICSEARCH_DOMAIN;
var indexName = process.env.INDEX_KEY;

var myRegexp = /([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*):([0-9]*) ([^ ]*)[:-]([0-9]*) ([-.0-9]*) ([-.0-9]*) ([-.0-9]*) (|[-0-9]*) (-|[-0-9]*) ([-0-9]*) ([-0-9]*) \"([^ ]*) ([^ ]*) (- |[^ ]*)\" \"([^\"]*)\" ([A-Z0-9-]+) ([A-Za-z0-9.-]*) ([^ ]*) \"([^\"]*)\" \"([^\"]*)\" \"([^\"]*)\" ([-.0-9]*) ([^ ]*) \"([^\"]*)\" \"([^\"]*)\" \"([^ ]*)\" \"([^\s]+?)\" \"([^\s]+)\" \"([^ ]*)\" \"([^ ]*)\"/;
//var logFailedResponses = false;
let logFailedResponses = true;

exports.handler = function(event, context, exit){
    // console.log('Received event:', JSON.stringify(event, null, 2));

    const currentDate = new Date();
    const year = currentDate.getFullYear();
    let month = (currentDate.getMonth() + 1).toString().padStart(2, ''); // Month is zero-based so we add 1
    if (month < 10) {
        month = '0' + month; // Add leading zero for single-digit months
    }
    let day = currentDate.getDate().toString().padStart(2, '');
    if (day < 10) {
         day = '0' + day; // Add leading zero for single-digit days
    }
    const formattedDate = year+'-'+month+'-'+day;

    // Get the object from the event and show its content type
    const bucket = event.Records[0].s3.bucket.name;
    const key = decodeURIComponent(event.Records[0].s3.object.key.replace(/\+/g, ' '));
    const params = {
       Bucket: bucket,
       Key: key,
    };

    s3.send(new GetObjectCommand(params)).then(data => {
        const chunks = [];
        data.Body.on('data', chunk => chunks.push(chunk));
        data.Body.on('end', () => {
            const buffer = Buffer.concat(chunks);
            zlib.gunzip(buffer, function(error, unzippedBuffer){
                if (error) {
                    console.log('Error uncompressing data', error);
                    return;
                }

                var logData = unzippedBuffer.toString('ascii');
                var array = logData.toString().split("\n");
                var bulkRequestBody = '';

                for(var i in array) {
                    var bulkRes = transform(array[i], key, formattedDate);
                    if(bulkRes != null){
                        bulkRequestBody += bulkRes;
                    }
                }

                // skip control messages
                if (!bulkRequestBody) {
                    context.succeed('Control message handled successfully');
                    return;
                }

                // post documents to the Amazon Elasticsearch Service
                post(bulkRequestBody, function(error, success, statusCode, failedItems) {
                    if (error) {
                        logFailure(error, failedItems);
                        context.fail(JSON.stringify(error));
                    } else {
                        // Unnecessary success logging removed for CloudWatch efficiency
                        context.succeed('Success');
                    }
                });
            });
        });
        data.Body.on('error', err => exit(err));
    }).catch(err => {
        console.log('ERROR ' + err);
        exit(err);
    });
};

function transform(array, key, formattedDate) {
    var source = {};
    var indeid = crypto.randomBytes(20).toString("hex");

    let [, type, time, elb, client_ip, client_port, target_ip, target_port, request_processing_time, target_processing_time, response_processing_time, elb_status_code, target_status_code, received_bytes, sent_bytes, request_type, request_url, request_protocol, user_agent_browser, ssl_cipher, ssl_protocol, target_group_arn, trace_id, domain_name, chosen_cert_arn, matched_rule_priority, request_creation_time, actions_executed, redirect_url, lambda_error_reason, target_port_list, target_status_code_list, classification, classification_reason ] = myRegexp.exec(array) || [];

    if(type!= null){    
        var url_pathname = new URL(request_url).pathname;
        var url = url_pathname.split("/");

        source['@id'] = indeid;
        source['@type'] = type;
        source['@time'] = time||new Date().toISOString();
        source['@elb'] = elb||'-';
        source['@client_ip'] = client_ip||'-';
        source['@client_port'] = client_port||'-';
        source['@target_ip'] = target_ip||'-';
        source['@target_port'] = target_port||'-';
        source['@request_processing_time'] = request_processing_time||'-';
        source['@target_processing_time'] = target_processing_time||'-';
        source['@response_processing_time'] = response_processing_time||'-';
        source['@elb_status_code'] = elb_status_code||'-';
        source['@target_status_code'] = target_status_code||'-';
        source['@received_bytes'] = received_bytes||'-';
        source['@sent_bytes'] = sent_bytes||'-';
        source['@request_type'] = request_type||'-';
        source['@request_url'] = request_url||'-';
        source['@request_protocol'] = request_protocol||'-';
        source['@user_agent_browser'] = user_agent_browser||'-';
        source['@ssl_cipher'] = ssl_cipher||'-';
        source['@ssl_protocol'] = ssl_protocol||'-';
        source['@target_group_arn'] = target_group_arn||'-';
        source['@trace_id'] = trace_id||'-';
        source['@domain_name'] = domain_name||'-';
        source['@chosen_cert_arn'] = chosen_cert_arn||'-';
        source['@matched_rule_priority'] = matched_rule_priority||'-';
        source['@request_creation_time'] = request_creation_time||new Date().toISOString();
        source['@actions_executed'] = actions_executed||'-';
        source['@redirect_url'] = redirect_url||'-';
        source['@lambda_error_reason'] = lambda_error_reason||'-';
        source['@target_port_list'] = target_port_list||'-';
        source['@target_status_code_list'] = target_status_code_list||'-';
        source['@classification'] = classification||'-';
        source['@classification_reason'] = classification_reason||'-';
        source['@message'] = array||'-';
        source['@s3_key'] = key||'-';
        source['@pathname'] = url_pathname||'-';
        source['@context_path'] = url[1]||'-';
        source['@path_1'] = url[2]||'-';
        source['@path_2'] = url[3]||'-';
        source['@path_3'] = url[4]||'-';
        source['@path_4'] = url[5]||'-';
        source['@timestamp'] = new Date().toISOString();
        source['@app_path'] = [(domain_name||'-'), (url[1]||'-')].join();

        var action = { "index": {} };
        action.index._index = indexName+'_'+formattedDate;
       // action.index._type = 'aws-elb';
        action.index._id = indeid;

        return [
            JSON.stringify(action),
            JSON.stringify(source),
        ].join('\n') + '\n';
    }else{
        return null;
    }
}    

function post(body, callback) {
    var requestParams = buildRequest(endpoint, body);

    var request = https.request(requestParams, function(response) {
        var responseBody = '';
        response.on('data', function(chunk) {
            responseBody += chunk;
        });

        response.on('end', function() {
            var info = JSON.parse(responseBody);
            var failedItems;
            var success;
            var error;

            if (response.statusCode >= 200 && response.statusCode < 299) {
                failedItems = info.items.filter(function(x) {
                    return x.index.status >= 300;
                });

                success = {
                    "attemptedItems": info.items.length,
                    "successfulItems": info.items.length - failedItems.length,
                    "failedItems": failedItems.length
                };
            }

            if (response.statusCode !== 200 || info.errors === true) {
                // prevents logging of failed entries, but allows logging
                // of other errors such as access restrictions
                delete info.items;
                error = {
                    statusCode: response.statusCode,
                    responseBody: info
                };
            }

            callback(error, success, response.statusCode, failedItems);
        });
    }).on('error', function(e) {
        callback(e);
    });
    request.end(requestParams.body);
}

function buildRequest(endpoint, body) {
    var endpointParts = endpoint.match(/^([^\.]+)\.?([^\.]*)\.?([^\.]*)\.amazonaws\.com$/);
    var region = endpointParts[2];
    var service = endpointParts[3];
    var datetime = (new Date()).toISOString().replace(/[:\-]|\.\d{3}/g, '');
    var date = datetime.substr(0, 8);
    var kDate = hmac('AWS4' + process.env.AWS_SECRET_ACCESS_KEY, date);
    var kRegion = hmac(kDate, region);
    var kService = hmac(kRegion, service);
    var kSigning = hmac(kService, 'aws4_request');

    var request = {
        host: endpoint,
        method: 'POST',
        path: '/_bulk',
        body: body,
        headers: {
            'Content-Type': 'application/json',
            'Host': endpoint,
            'Content-Length': Buffer.byteLength(body),
            'X-Amz-Security-Token': process.env.AWS_SESSION_TOKEN,
            'X-Amz-Date': datetime
        }
    };

    var canonicalHeaders = Object.keys(request.headers)
        .sort(function(a, b) { return a.toLowerCase() < b.toLowerCase() ? -1 : 1; })
        .map(function(k) { return k.toLowerCase() + ':' + request.headers[k]; })
        .join('\n');

    var signedHeaders = Object.keys(request.headers)
        .map(function(k) { return k.toLowerCase(); })
        .sort()
        .join(';');

    var canonicalString = [
        request.method,
        request.path, '',
        canonicalHeaders, '',
        signedHeaders,
        hash(request.body, 'hex'),
    ].join('\n');

    var credentialString = [ date, region, service, 'aws4_request' ].join('/');

    var stringToSign = [
        'AWS4-HMAC-SHA256',
        datetime,
        credentialString,
        hash(canonicalString, 'hex')
    ] .join('\n');

    request.headers.Authorization = [
        'AWS4-HMAC-SHA256 Credential=' + process.env.AWS_ACCESS_KEY_ID + '/' + credentialString,
        'SignedHeaders=' + signedHeaders,
        'Signature=' + hmac(kSigning, stringToSign, 'hex')
    ].join(', ');

    return request;
}

function hmac(key, str, encoding) {
    return crypto.createHmac('sha256', key).update(str, 'utf8').digest(encoding);
}

function hash(str, encoding) {
    return crypto.createHash('sha256').update(str, 'utf8').digest(encoding);
}

function logFailure(error, failedItems) {
    if (logFailedResponses) {
        console.log('Error: ' + JSON.stringify(error, null, 2));

        if (failedItems && failedItems.length > 0) {
            console.log("Failed Items: " +
                JSON.stringify(failedItems, null, 2));
        }
    }
}
