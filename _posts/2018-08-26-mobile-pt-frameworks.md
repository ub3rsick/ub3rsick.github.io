---
layout: post
title: Setting up PASSIONFRUIT, OBJECTION and DROZER
---


## Setting up passionfruit
1. Install pre-requisite nodejs for respective os from https://nodejs.org/en/
2. Clone [Passionfruit](https://github.com/chaitin/passionfruit) to desktop or desired path.
**
```git clone https://github.com/chaitin/passionfruit.git
```
**
or download zip file through browser and extract.
3. Open the terminal and cd into the passionfruit directory.
4. To install npm dependencies and build the frontend, run the following command.

**`npm install`**

5. To build the bundle run below command

**`npm run build`**

6. Start server using below command

**`npm start`**

7. Open **http://localhost:31337** in browser to access the passionfruit web ui.
8. Connect your iDevice (which has frida-server running in background) to your pc or mac via USB.

Once setup, next time when you have to start passionfruit, navigate to passionfruit directory and just run **`npm start`**.


### Note:
Require frida-server running on the jailbroken device
- ssh to device and navigate to frida-server binary location and run 
	**`./frida-server &`**
	or if you have it added to PATH, run the following
	**`frida-server &`**

## Setting up Objection

Install pre-requisite frida on host machine (OSX/Linux) with:
	**`sudo pip install frida`**

Its better to install objection in a virtual environment.
1. Clone [Objection Github Repo](https://github.com/sensepost/objection/)
2. Install virtualenv
	**`pip install virtualenv`**
	or if already have it, update it
	**`pip install virtualenv --upgrade`**
3. Create a new python3 virtual environment for objection with following command.
	**`virtualenv --python=python3 ~/objection-python3-env`**
4. Activate your new python virtual environment with:
	**`source ~/objection-python3-env/bin/activate`**
5. Next, start the installation using pip3 with:
	**`pip3 install -U objection`**
	Once the dependencies are installed, the objection command should be available in your PATH.

To start analysing an app with objection, follow below steps.
1. activate objection virtualenv by running:
	**`source ~/objection-python3-env/bin/activate`**
2. To find application process name, with app running mobile device, and connected to the host machine via USB, run the following
	**`frida-ps -U` ** - This command lists all running processes on the device, you can manually look for the app name or do the below.
	**`frida-ps -U | grep app_name_substring`**
3. Having obtained app name hook it with objection.
	**`objection --gadget "app-name" explore`**
4. Now objection console will be opened.

Useful objection commands and wiki - https://github.com/sensepost/objection/wiki/Using-objection

## Setting up drozer for android assessments.

AndroidTamer4 comes with drozer preconfigured. VM can be downloaded from
[here](https://androidtamer.com/tamer4-release). or  if you want to configure drozer on your linux machine follow the below steps.
1. Building Python wheel
	
	**`git clone https://github.com/mwrlabs/drozer.git`**
	**`cd drozer`**
	**`python setup.py bdist_wheel`**

2. Installing Python wheel

**`sudo pip install drozer-2.x.x-py2-none-any.whl`**

**Note:** The file name drozer-2.x.x-py2-none-any.whl might be different, the x.x number might be different. The file will be in bdist directory.

3. Once installation finishes, drozer command will be available.

### Install drozer-agent apk in android device.
- Download latest agent apk from [here](https://github.com/mwrlabs/drozer/releases/).

**`adb install drozer-agent-2.x.x.apk`**

Now you have everything to analyze apps with drozer.

Analyzing apps with drozer.
1. open drozer client app on android device and click to start server. (default port 31415, can be changed)
2. Connect android device with USB debugging enabled on to host machine via usb.
3. setup port forward with adb.

**`adb forward tcp:31415 tcp:31415`**

4. Connect to drozer console.

**`drozer console connect`**

5. Now you are in drozer CLI.
