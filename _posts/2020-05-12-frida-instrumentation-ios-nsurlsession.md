---
layout: post
title: "Frida Runtime Instrumentation [iOS:NSURLSession]"
---

Tracing iOS NSURLSession instance methods and instrumenting those methods to log all the requests and responses. 

<!-- more -->

## Objectives
- Find out which Objective C class, the application is using for HTTP/HTTPS communications
- Hook the identified methods (class methods / instance methods) using frida and display the Requests and Responses.
- Acheive above objectives only using frida (No reversing, traffic interception via web proxy)


## Identify The Target Application Name and Identifier
Listing all the connected devices: `frida-ls-devices`
```
(objEnv) kali@kali:~/Desktop/BipBupBop/Frida$ frida-ls-devices
Id                                        Type    Name
----------------------------------------  ------  ------------
local                                     local   Local System
061a9edb360*************705a9701ac78d9fd  usb     iOS Device
tcp                                       remote  Local TCP
```
The test iOS device is the one connected via USB. To list all the installed applications on the device, run `frida-ps -Uia`.

`-U`: Tell frida to connect to USB Device

`-a`: List only applications

`-i`: Include all installed applications


```
(objEnv) kali@kali:~/Desktop/BipBupBop/Frida$ frida-ps -Uia
PID  Name            Identifier
-  --------------  --------------------------------
-  Aarogya Setu    in.nic.arogyaSetu
...
```
Our test subject is [Aarogya Setu](https://apps.apple.com/in/app/aarogyasetu/id1505825357) iOS application.

**Disclaimer:** The selection of application has nothing to do with any of the heated verbal exchanges happening in social media.

## Dumping Class Names
```python
# Author: Rizal Muhammed [UB3RSiCK]
# Date: 11 May 2020

import frida, sys

classnames =    """
                Object.keys(ObjC.classes).forEach(function(className){
                        console.log(className)
                });
                """

device = frida.enumerate_devices()[2]
#session = device.attach("Aarogya Setu")

pid = device.spawn(["in.nic.arogyaSetu"])
session = device.attach(pid)

script = session.create_script(classnames)
script.load()
```
The script lists all the class names in the application. We are interested only in Objective C classes used for HTTP/HTTPS requests such as **NSURLConnection** and **NSURLSession**. To filter out only the output of the python script and run it through grep.

`python aarogya_setu.py | grep -iE "nsurlsession|nsurlconnection"`

```
(objEnv) kali@kali:~/Desktop/BipBupBop/Frida/AaarogyaSetu$ python aarogya_setu.py | grep -iE "nsurlsession|nsurlconnection"
FIRInstallationsURLSessionResponse
WebCoreNSURLSessionDataTask
WebCoreNSURLSession
_GEONSURLSessionWaiter
GEONSURLSessionTaskState
NSURLSessionConfiguration
NSURLSessionTaskMetrics
NSURLSessionTaskTransactionMetrics
NSURLSessionTaskHTTPAuthenticator
NSURLSessionTaskLocalHTTPAuthenticator
NSURLSessionTaskBackgroundHTTPAuthenticator
NSURLConnectionInternal
NSURLConnectionInternalConnection
NSURLConnectionInternalBackgroundDownload
NSURLSessionTaskDependency
NSURLSessionTaskDependencyTree
NSURLSessionTaskDependencyDescription
__NSURLSessionTaskDependencyResourceIdentifier
__NSURLSessionStatistics
NSURLSessionStreamTaskTester
NSURLConnection
NSURLSessionTask
NSURLSessionStreamTask
NSURLSessionDataTask
NSURLSessionUploadTask
NSURLSessionAVAggregateAssetDownloadTask
NSURLSessionAVAssetDownloadTask
NSURLSessionDownloadTask
NSURLSession
__NSURLSessionLocal
```

## Tracing Calls To Any Class/Instance Methods of NSURLSession Class
We identified that the application is using NSURLSession class to make requests to the backend server.
```
frida-trace -f in.nic.arogyaSetu -m "*[NSURLSession *]" -U
-f PKGNAME: spawn application with this package name
-m OBJC_METHOD, --include-objc-method=OBJC_METHOD
```
iOS methods syntax: **+/-[ClassName function/methodname]**

The above frida-trace command will trace every class and instance methods of **NSURLSession** class.

- Intercept Objective C methods (-m)
- Intercept both classmethods (+[]) and instance methods (-[])

![NSURLSessionTracing](/assets/ios_hook_nsurlsession/trace_nsurlsession.png)

It can be seen that frida also generated handlers for all methods in NSURLSession class as well.
![NSURLSessionHandlers](/assets/ios_hook_nsurlsession/tracing_350_functions.png)


We see below instance methods being invoked when using the mobile application. Also the method handlers are written to `__handlers__` directory inside current directory. Frida also assumes the arguments for the method as well.
```
-[NSURLSession uploadTaskWithRequest:0x28017c800 fromData:0x280d39b90 completionHandler:0x28199a980]
```
![uploadTaskWithRequest](/assets/ios_hook_nsurlsession/uploadTaskWithRequest.png)

```
-[NSURLSession downloadTaskWithRequest:0x28017d570 completionHandler:0x16f1183f8]
```
![downloadTaskWithRequest](/assets/ios_hook_nsurlsession/downloadTaskWithRequest.png)

```
-[NSURLSession dataTaskWithRequest:0x280171e10 completionHandler:0x280d45e00]
```
![dataTaskWithRequest](/assets/ios_hook_nsurlsession/dataTaskWithRequest.png)


## -[NSURLSession uploadTaskWithRequest: fromData: completionHandler:]
The handler generated by frida-trace for this instance method call is as follows.

![uploadTaskWithRequestHandler](/assets/ios_hook_nsurlsession/uploadTaskWithRequest_handler.png)

frida guesses the following parameters.
- uploadTaskWithRequest = args[2]
- fromData = args[3]
- completionHandler = args[4]

The definition for the instance method is as follows:

Reference: [https://developer.apple.com/documentation/foundation/nsurlsession/1411518-uploadtaskwithrequest?language=objc](https://developer.apple.com/documentation/foundation/nsurlsession/1411518-uploadtaskwithrequest?language=objc)
```
- (NSURLSessionUploadTask *)uploadTaskWithRequest:(NSURLRequest *)request 
          fromData:(NSData *)bodyData 
          completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler;
```
Now we know the type of each argument,
- args[2] = NSURLRequest
- args[3] = NSData
- args[4] = void function (data, response, error)

To get the URL from the NSURLRequest parameter args[2], we need to know the definition of NSURLRequest.

NSURLRequest: [https://developer.apple.com/documentation/foundation/nsurlrequest?language=objc](https://developer.apple.com/documentation/foundation/nsurlrequest?language=objc)
```
@interface NSURLRequest : NSObject
```
NSURLRequest allows Accessing Request Components
- HTTPMethod : The HTTP request method.
- URL : The URL being requested.
- HTTPBody : The request body.
- HTTPBodyStream : The request body as an input stream.
- mainDocumentURL : The main document URL associated with the request.

So we can access the request URL as follows:
```
ObjC.Object(args[2]).URL().absoluteString()
```
>> ObjC.Object(ptr) - tells frida to treat the ptr as an Objective C instance/object so that we can access its properties and methods. In this case, we need to access the properties and methods of NSURLRequest.

```javascript
		var method = ObjC.classes.NSURLSession["- uploadTaskWithRequest:fromData:completionHandler:"];
        Interceptor.attach(method.implementation, {
                onEnter: function(args){
                        console.log('uploadTaskWithRequest: URL: ' + ObjC.Object(args[2]).URL().absoluteString());
                }
        });
```
Use frida to load the javascript file to the application.

`frida -l aarogya_setu.js -f "in.nic.arogyaSetu" -U --no-pause`

![uploadTaskWithRequest_URL](/assets/ios_hook_nsurlsession/uploadTaskWithRequest_URL.png)

We can now see that the instance method issending a request to one firebase logging end point.

## -[NSURLSession downloadTaskWithRequest: completionHandler:]
frida-trace generated handler:

![downloadTaskWithRequestHandler](/assets/ios_hook_nsurlsession/downloadTaskWithRequest_handler.png)

The definition of the instance method:

Reference: [https://developer.apple.com/documentation/foundation/nsurlsession/1411511-downloadtaskwithrequest?language=objc](https://developer.apple.com/documentation/foundation/nsurlsession/1411511-downloadtaskwithrequest?language=objc)
```
- (NSURLSessionDownloadTask *)downloadTaskWithRequest:(NSURLRequest *)request 
        completionHandler:(void (^)(NSURL *location, NSURLResponse *response, NSError *error))completionHandler;
```
Similar to the previous one, attach to the instance method and log URL from NSURLRequest object.
```javascript
        var downloadTaskWithRequestMethod = ObjC.classes.NSURLSession["- downloadTaskWithRequest:completionHandler:"];
        Interceptor.attach(downloadTaskWithRequestMethod.implementation, {
                onEnter: function(args){
                        console.log("downloadTaskWithRequestMethod: URL: " + ObjC.Object(args[2]).URL().absoluteString());
                }
        });

```
Load the modified javascript file to the application.

`frida -l aarogya_setu.js -f "in.nic.arogyaSetu" -U --no-pause`

![downloadTaskWithRequest_URL](/assets/ios_hook_nsurlsession/downloadTaskWithRequest_URL.png)

In addition to the firebase loggin request, we are now able to see request to crashlytics.

## -[NSURLSession dataTaskWithRequest: completionHandler:]
frida-trace generated handler:

![dataTaskWithRequestHandler](/assets/ios_hook_nsurlsession/dataTaskWithRequest_handler.png)

The definition of the instance method:

Reference: [https://developer.apple.com/documentation/foundation/nsurlsession/1407613-datataskwithrequest](https://developer.apple.com/documentation/foundation/nsurlsession/1407613-datataskwithrequest)
```
- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request 
        completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler;
```
The instance method interceptor implementation is similar to previous ones, except we will hook completion handler as well to display the response.
```javascript
        // args[2] = dataTaskWithRequest: NSURLRequest
        // args[3] = completionHandler:
        var dataTaskWithRequestMethod = ObjC.classes.NSURLSession["- dataTaskWithRequest:completionHandler:"];
        var OGCompletionHandler_DTWRM = null;

        Interceptor.attach(dataTaskWithRequestMethod.implementation, {
                onEnter: function(args){
                        console.log("dataTaskWithRequestMethod: HTTPMethod: " + ObjC.Object(args[2]).HTTPMethod());
                        console.log("dataTaskWithRequestMethod: URL: " + ObjC.Object(args[2]).URL().absoluteString());
                        console.log("dataTaskWithRequestMethod: HTTPBody (NSData): " + ObjC.Object(args[2]).HTTPBody());

                        // HTTPBody is of NSData type
                        // https://developer.apple.com/documentation/foundation/nsurlrequest/1411317-httpbody?language=objc
                        // @property(readonly, copy) NSData *HTTPBody;
                        var body_nsdata = ObjC.Object(args[2]).HTTPBody(); 

                        // https://codeshare.frida.re/@lichao890427/ios-utils/
                        // NSData to NSString
                        var body_nsstring = ObjC.classes.NSString.alloc().initWithData_encoding_(body_nsdata, 4);
                        console.log("dataTaskWithRequestMethod: HTTPBody (NSString): " + body_nsstring);


                        // https://github.com/theart42/hack.lu/blob/master/IOS/Notes/02-HTTPS/00-https-hooks.md
                        var completionHandler = new ObjC.Block(args[3]);
                        OGCompletionHandler_DTWRM = completionHandler.implementation;

                        completionHandler.implementation = function(data_nsdata, response_nsurlresponse, error_nserror){
                                console.log("dataTaskWithRequestMethod: Response Headers: " + ObjC.Object(response_nsurlresponse));
                                // Convert NSData to NSString
                                var data_nsstring = ObjC.classes.NSString.alloc().initWithData_encoding_(data_nsdata, 4);

                                console.log("dataTaskWithRequestMethod: Response Data: " + data_nsstring)

                                // return original completion handler
                                return OGCompletionHandler_DTWRM(data_nsdata, response_nsurlresponse, error_nserror);
                        }
                }
        });

```
Load the modified javascript file to the application.

`frida -l aarogya_setu.js -f "in.nic.arogyaSetu" -U --no-pause`

![dataTaskWithRequest_requests_response_URL](/assets/ios_hook_nsurlsession/dataTaskWithRequest_requests_response_URL.png)

We can now see other requests originating from the application and their responses as well. We see a request to the following API endpoint:

`https://fp.swaraksha.gov.in/api/v1/app/config`

we can also see the response for this request as well. Unfortunately it is an **HTTP 403 Forbidden** response.

## Putting It All Together
The complete hooking script.
```javascript
// Author: Rizal Muhammed [UB3RSiCK]
// Date: 11 May 2020
// Desc: Frida script to intercept Aarogya Setu iOS App NSURLSession instance methods
//		 and display request and response contents

// Check whether the current process has an Objective-C runtime loaded. 
// Do not invoke any other ObjC properties or methods unless this is the case
if(ObjC.available){

	//-[NSURLSession uploadTaskWithRequest:' + ObjC.Object(args[2]).URL().absoluteString() + ' fromData:' + ObjC.Object(args[3]).bytes() + ' completionHandler:' + args[4] + ']');

	// https://developer.apple.com/documentation/foundation/nsurlsession/1411518-uploadtaskwithrequest?language=objc
	//- (NSURLSessionUploadTask *)uploadTaskWithRequest:(NSURLRequest *)request 
        //                            fromData:(NSData *)bodyData 
        //   		              completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler;
	// args[0] = Self
	// args[1] = selector/ method identifier

	// https://developer.apple.com/documentation/foundation/nsurlrequest?language=objc
	// args[2] is NSURLRequest and the the followin request components are accessible.
	// HTTPMethod, URL, HTTPBody, HTTPBodyStream, mainDocumentURL

	// https://developer.apple.com/documentation/foundation/nsdata?language=objc
	// args[3] is NSData. underlying bytes can be accessed by bytes, getBytes:length:, etc.
	var method = ObjC.classes.NSURLSession["- uploadTaskWithRequest:fromData:completionHandler:"];
	Interceptor.attach(method.implementation, {
		onEnter: function(args){
			console.log("-".repeat(20));
			console.log("-[NSURLSession uploadTaskWithRequest: fromData: completionHandler:]")
			console.log('uploadTaskWithRequest: URL: ' + ObjC.Object(args[2]).URL().absoluteString());
			console.log("-".repeat(20));
			//console.log('uploadTaskWithRequest: Data Bytes: ' + ObjC.Object(args[3]).bytes());
			//var data = ObjC.Object(args[3]);
			//var s_data = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
			//console.log('uploadTaskWithRequest: Data: ' + s_data);
		}
	});


	//-[NSURLSession downloadTaskWithRequest:0x283c8e150 completionHandler:0x16f53c3f8]
	// https://developer.apple.com/documentation/foundation/nsurlsession/1411511-downloadtaskwithrequest?language=objc
	//- (NSURLSessionDownloadTask *)downloadTaskWithRequest:(NSURLRequest *)request 
        //                            completionHandler:(void (^)(NSURL *location, NSURLResponse *response, NSError *error))completionHandler;

	var downloadTaskWithRequestMethod = ObjC.classes.NSURLSession["- downloadTaskWithRequest:completionHandler:"];
	Interceptor.attach(downloadTaskWithRequestMethod.implementation, {
		onEnter: function(args){
			console.log("-".repeat(20));
			console.log("-[NSURLSession downloadTaskWithRequest: completionHandler:]")
			console.log("downloadTaskWithRequestMethod: URL: " + ObjC.Object(args[2]).URL().absoluteString());
			console.log("-".repeat(20));
			//console.log("downloadTaskWithRequestMethod: mainDocumentURL: " + ObjC.Object(args[2]).mainDocumentURL());
		}
	});


	// -[NSURLSession dataTaskWithRequest:0x282a680e0 completionHandler:0x28266b480]
	// https://developer.apple.com/documentation/foundation/nsurlsession/1407613-datataskwithrequest
	// - (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request 
	//	                    completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler;
	// args[2] = dataTaskWithRequest: NSURLRequest
	// args[3] = completionHandler:
	var dataTaskWithRequestMethod = ObjC.classes.NSURLSession["- dataTaskWithRequest:completionHandler:"];
	var OGCompletionHandler_DTWRM = null;

        Interceptor.attach(dataTaskWithRequestMethod.implementation, {
                onEnter: function(args){
			console.log("-".repeat(20));
			console.log("-[NSURLSession dataTaskWithRequest: completionHandler:]");
                        console.log("dataTaskWithRequestMethod: HTTPMethod: " + ObjC.Object(args[2]).HTTPMethod());
                        console.log("dataTaskWithRequestMethod: URL: " + ObjC.Object(args[2]).URL().absoluteString());
                        console.log("dataTaskWithRequestMethod: HTTPBody (NSData): " + ObjC.Object(args[2]).HTTPBody());

			// HTTPBody is of NSData type
			// https://developer.apple.com/documentation/foundation/nsurlrequest/1411317-httpbody?language=objc
			// @property(readonly, copy) NSData *HTTPBody;
			var body_nsdata = ObjC.Object(args[2]).HTTPBody(); 

			// https://codeshare.frida.re/@lichao890427/ios-utils/
			// NSData to NSString
			var body_nsstring = ObjC.classes.NSString.alloc().initWithData_encoding_(body_nsdata, 4);
                        console.log("dataTaskWithRequestMethod: HTTPBody (NSString): " + body_nsstring);


			// https://github.com/theart42/hack.lu/blob/master/IOS/Notes/02-HTTPS/00-https-hooks.md
			var completionHandler = new ObjC.Block(args[3]);
			OGCompletionHandler_DTWRM = completionHandler.implementation;

			completionHandler.implementation = function(data_nsdata, response_nsurlresponse, error_nserror){
				console.log("dataTaskWithRequestMethod: Response Headers: " + ObjC.Object(response_nsurlresponse));

				// Convert NSData to NSString
				var data_nsstring = ObjC.classes.NSString.alloc().initWithData_encoding_(data_nsdata, 4);

				console.log("dataTaskWithRequestMethod: Response Data: " + data_nsstring)

				// return original completion handler
				return OGCompletionHandler_DTWRM(data_nsdata, response_nsurlresponse, error_nserror);
			}
			console.log("-".repeat(20));
                }
        });
}
```

**Submitting OTP generation request:**


![OTPGen](/assets/ios_hook_nsurlsession/gen_otp_50.PNG)

We can see the request and its response in frida console log.
![GenOTPReq](/assets/ios_hook_nsurlsession/dataTaskWithRequest_gen_otp.png)

**Submitting OTP for verification:**


![ver_otp](/assets/ios_hook_nsurlsession/ver_otp_50.PNG)


OTP verification request and response.
![VerOTPReqResp](/assets/ios_hook_nsurlsession/dataTaskWithRequest._validateOTP.png)

**_PS: Tests are done from outside the country (INDIA), the application api's may be geo restricted to INDIA only. This would explain the HTTP 403 Forbidden responses._**
