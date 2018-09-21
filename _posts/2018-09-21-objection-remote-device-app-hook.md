---
layout: post
title: (Objection) Mobile apps on remote device
---
This post describes how to hook applications running on a remote device (iOS/Android) using Objection. Describes how to setup port forwarding.

<!-- more -->

## Installing frida-tools (CLI tools) on Linux/Mac
Use the following commands to install frida-tools.

**```pip install frida-tools```**

If **frida-tools** already installed and wants to update to latest version.

**```pip install frida-tools --upgrade```**

## Application running on Remote iOS (jailbroken) device
#### Install Frida (frida-server) on iDevice
1. Add following repo to cydia - **```https://build.frida.re```**
2. Search for 'frida' and install frida.
3. Once installation finishes **frida-server** will be present in path and listening on port **27042** on the iDevice.

#### Port forward local port 27042 to remote port 27042
From PC/Mac terminal, run the following command to forward local port 27042 to remote port 27042.

**```ssh -L 27042:127.0.0.1:27042 root@<iDevice_ip>```**

Enter iDevice root password and leave the terminal as is.

#### List applications running on device
Make sure frida-tools is upto date on the pc/MAC.

List running applications : **```frida-ps -R```**

##### Sample Output
```
(virt-python3)  rizal@rizals-Mac$ frida-ps -R
 PID  Name
----  --------------------------------------------------------
2712  Camera
 980  InCallService
2001  Mail
1720  Messages
 790  MusicUIService
2715  Photos
1726  Settings
1253  User Authentication
3424  WhatsApp
....
<snipped>
....
```

#### Hook application on remote iDevice with Objection
Command: **```objection --network --gadget "Application Name" explore```**
> The **```--network```** flag tells objection to connect using a network connection instead of USB.

##### Sample Output
```
(virt-python3)  rizal@rizals-Mac$ objection --network --gadget "Reddit" explore

     _     _         _   _
 ___| |_  |_|___ ___| |_|_|___ ___
| . | . | | | -_|  _|  _| | . |   |
|___|___|_| |___|___|_| |_|___|_|_|
        |___|(object)inject(ion) v1.4.3

     Runtime Mobile Exploration
        by: @leonjza from @sensepost

[tab] for command suggestions
com.reddit.Reddit on (iPhone: 11.3.1) [net] #
```

## Application running on remote Android (rooted) device

#### Install frida-server on Android device
Connect to remote device with ADB.

**`adb connect <android_device_ip>`**

Go to frida [releases](https://github.com/frida/frida/releases) page and get the **frida-server** binary for android. Push it onto android device and set appropriate permissions.

**`adb push frida-server /data/local/tmp/ `**

**`adb shell "chmod 755 /data/local/tmp/frida-server"`**

Run frida-server on android device.

**`adb shell "/data/local/tmp/frida-server &"`**


#### Port forward local port 27042 to remote port 27042

**`adb forward tcp:27042 tcp:27042`**

If port forwarding is not setup, the following error will come up.
```
(objection-py3env) android@tamer:~$ frida-ps -R 
Failed to enumerate processes: unable to connect to remote frida-server
```
##### Sample output once port forward is setup
```
(objection-py3env) android@tamer:~$ frida-ps -R 
 PID  Name
----  -------------------------------
 126  adbd
1966  android.ext.services
2177  android.process.acore
2084  android.process.media
1249  audioserver
 245  batteryd
1250  cameraserver
2162  com.android.calendar
```
#### Hook application on remote Android with Objection
Command: **`objection --gadget "Application Name" explore`**
##### Sample Output
```
(objection-py3env) android@tamer:~$ objection --gadget "net.fxxl" explore

     _     _         _   _
 ___| |_  |_|___ ___| |_|_|___ ___
| . | . | | | -_|  _|  _| | . |   |
|___|___|_| |___|___|_| |_|___|_|_|
        |___|(object)inject(ion) v1.4.3

     Runtime Mobile Exploration
        by: @leonjza from @sensepost

[tab] for command suggestions

net.fxxl on (Android: 7.0) [usb] # android sslpinning disable
Job: d9b3a203-acda-44d5-a179-5b4e84d8816a - Starting
[5b4e84d8816a] [android-ssl-pinning-bypass] Custom, Empty TrustManager ready
[5b4e84d8816a] [android-ssl-pinning-bypass] OkHTTP 3.x Found
[5b4e84d8816a] [android-ssl-pinning-bypass] TrustManagerImpl
Job: d9b3a203-acda-44d5-a179-5b4e84d8816a - Started
```
