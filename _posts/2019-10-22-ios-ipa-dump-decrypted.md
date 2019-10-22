---
layout: post
title: "Dumping Decrypted IPA [Jaibroken iPhone 5s iOS 12.2]"
---

This post demonstrates how to dump decrypted iOS app IPA from a jailbroken iOS device. I'm using a Jailbroken iPhone 5s running iOS 12.2 to demostrate the entire process.

<!-- more -->

## The Environment Setup

I'll be using the [frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump) tool to dump the IPA from a jailbroken device. The aforementioned script is written in Python, both Python2 and Python3 version are available. I'll be using the Python2 version for this post.

There are several dependencies for the script to run properly and do its magic. All the requirements are specified in the 'requirements.txt' file once you clone the [frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump) git repo.

I'll setup a new Python2 virutal environment and install all the dependecies required in the virtual environment. This way I don't need to worry about any messing up dependencies for other applications.

### Python2 Virtual Environment

Creating a new Python2 virtual environment using [virtualenv](https://pypi.org/project/virtualenv/). If it is not available in path, use below command to install it.

`pip install virtualenv`

Use below command to create a Python2 virtual environment.

`virtualenv --python=python2 p2env`

Activate the Python2 environment.

`source p2env/bin/activate`

Now we are inside the Python2 environment.

![python2-venv](/assets/ios_dump_ipa/p2venv.png)

### iOS Device Setup

The device should be Jailbroken. I'm using a iPhone 5s running on iOS 12.2 jailbroken using [unc0ver - undecimus](https://github.com/pwn20wndstuff/Undecimus).

#### frida-server
[frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump) requires [frida-server](https://github.com/frida/frida/releases) to be running on the iOS device. The easiest way to do this is via Cydia on the device. Add the following source repo in Cydia.

`http://build.frida.re`

![frida-repo-add](/assets/ios_dump_ipa/frida-repo.png) | ![frida-installed](/assets/ios_dump_ipa/frida-installed.png)


Once the source is added, you can search for frida in Cydia. Install frida from Cydia, once installation is finished, frida-server will be running on th device and listening on its default port 27042.

To verify frida-server is running on the device, list the processes running on the device using **frida-ps**.

`frida-ps -U`

![frida-ps](/assets/ios_dump_ipa/frida-ps.png)

#### OpenSSH

SSH should running on the device. With [undecimus](https://github.com/pwn20wndstuff/Undecimus), OpenSSH must be installed from Cydia. Once installed, you can ssh to the device as root with default password 'alpine'.

If you already have SSH running on your device, skip this step.

### SSH Port Forwarding

For the [frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump) to work, it should be able to SSH/SCP to the device via USB. For this port forwarding should be done.

Using [tcprelay.py](https://github.com/rcg4u/iphonessh/blob/master/python-client/tcprelay.py) from [iphonessh](https://github.com/rcg4u/iphonessh) repo to forward local port 2222 to remote port 22 via USB.

`python iphonessh/python-client/tcprelay.py -t 22:2222 &`

![port-forward](/assets/ios_dump_ipa/tcprelay.png)

Now we can SSH to the iOS device connected via USB.

`ssh root@localhost -p 2222`

![ssh-via-usb](/assets/ios_dump_ipa/ssh.png)

Note: If you have iproxy instead, you can use the following command.

`iproxy 22:2222`

### Installing Requirements

Clone the [frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump) git repo and navigate inside the directory. 

![repo-clone](/assets/ios_dump_ipa/clone-frida-ios-dump.png)

Run the following command from within the Python2 virtual envinronment to install all the requirements.

`pip install -r requirements.txt`

Once the installation is finished, we are ready to dump decrypted IPAs.

## Dumping Decrypted IPAs

We are done with the pre-requisites now.
- Python2 virtual enviroment.
- frida-server listening on Jailbroken device.
- Port forwarding local port 2222 to remote port 22. 
- Installed all requirements in the Python2 envinronment.

With the iOS device connected to the PC/MAC via USB. Run the following command to dump decrypted IPA. Make sure the application for which we are going to dumpt the IPA is not running on the iOS device.

`python dump.py <application_name>`

Once the process is done, you will have the decrytped application IPA in the current working directory. 

![dump-decrypted-ipa](/assets/ios_dump_ipa/ipa_dump.gif)
