---
layout: post
title: "Jailbreak Detection and Bypass Techniques [iOS 12.2]"
---

In this blog post we will look at different ways in which developers can implment jailbreak detection in their applications and the methods to bypass them.

<!-- more -->

## Jailbreak Detection Methods and Bypasses

Below are the different methods used to determine whether the current device is jailbroken or not.

### Detection Based on Jailbreak Specific Files

When a device is jailbroken, many unix utilities (apt, su etc.), applications (Cydia.app) are written to the file system at specific locations. During runtime, an app can look if there are files existing at these paths to determine if the device is jailbroken or not. Below is a list of paths to files, applications which are written to the file system once a device is jailbroken.

`
/Applications/Cydia.app
/private/var/stash
/private/var/lib/apt
/private/var/tmp/cydia.log
/private/var/lib/cydia
/private/var/mobile/Library/SBSettings/Themes
/Library/MobileSubstrate/MobileSubstrate.dylib
/Library/MobileSubstrate/DynamicLibraries/Veency.plist
/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist
/System/Library/LaunchDaemons/com.ikey.bbot.plist
/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist
/var/cache/apt
/var/lib/apt
/var/lib/cydia
/var/log/syslog
/var/tmp/cydia.log
/bin/bash
/bin/sh
/usr/sbin/sshd
/usr/libexec/ssh-keysign
/usr/sbin/sshd
/usr/bin/sshd
/usr/libexec/sftp-server
/etc/ssh/sshd_config
/etc/apt
`

Note: This no way a complete list.

Let us look at a simple sample implementation in which the application looks for the presence of `/Applications/Cydia.app`. The application will show an alert depending on the result.

![cydia_check](/assets/ios-jb-detect-bypass/01_fscheck01.png)

Lets run this app on a jailbroke device to see if it works.

![install](/assets/ios-jb-detect-bypass/02_install.png) | ![run1](/assets/ios-jb-detect-bypass/03_jbd.png)

Let us analyze the application executable in hopper disassembler. Find the application executable location.

![jbDetectPath](/assets/ios-jb-detect-bypass/04_binpath.png)

Connect to the device using cyber duck (or use sftp/scp to device from terminal).

![cyberduck_con](/assets/ios-jb-detect-bypass/05-cd-con.png)

Navigate to the application directory.

![cyberduck_nav](/assets/ios-jb-detect-bypass/06-cd-nav.png)

Pull the application binary to the host machine.

![cyberduck_pull](/assets/ios-jb-detect-bypass/07-cd-pull.png)

Open the application binary in Hopper disassembler.(/assets/ios-jb-detect-bypass/10-jbmethod.png)

![hopper-bin](/assets/ios-jb-detect-bypass/08-open-bin.png)

Go with defaults.

![hopper-def](/assets/ios-jb-detect-bypass/09-hopper-def.png)

Once hopper finishes disassembling the application binary into assembly code, we can look for procedures, strings in the application.

![jb-method](/assets/ios-jb-detect-bypass/10-jbmethod.png)

The pseudo code for the assembly code can be seen in hopper. The pseudo code is easily understandable (atleast in this case) and one can easily determine what it does.

![pseudo](/assets/ios-jb-detect-bypass/11-pseudo.png)

Hopper also provides a control flow graph (CFG) view as well.

![cfg](/assets/ios-jb-detect-bypass/12-cfg.png)

#### Bypassing FileSystem Based Checks By Patching

Once we understand the jailbreak detection implementation, next step would be to bypass it. When we inspect the assembly code/CFG, we can see that irrespective of the checks performed, the decision is determined by a single instruction as seen below.

![tbz](/assets/ios-jb-detect-bypass/13-tbz.png)

The **tbz** arm instruction tests a bit and branches if zero to the specified label.

![tbz-arm](/assets/ios-jb-detect-bypass/14-tbz-arm.png)

In our case the instruction is `tbz w8, 0x0, loc_1000064ec`; this will check if the w8 register is zero and if zero the control will passed to the label `loc_1000064ec` from where the code which shows alert for showing device not jailbroken starts.

![stock_device_alert](/assets/ios-jb-detect-bypass/15-alert-stock.png)

Now lets patch this instruction to branch to the label `loc_1000064ec` irrespective of the value of `w8` register. Goto modify menu in hopper and select assemble instruction.

![assemble](/assets/ios-jb-detect-bypass/16-assemble.png)

Replace the instruction with just a branch instruction to the desired label.
`b loc_1000064ec`

![patch1](/assets/ios-jb-detect-bypass/17-patch1.png)
![patch2](/assets/ios-jb-detect-bypass/18-patch2.png)

Control flow graph after patching.

![patch-cfg](/assets/ios-jb-detect-bypass/19-patch-cfg.png)

Pseudo Code after patching.

![patch-pseudo](/assets/ios-jb-detect-bypass/20-patch-pseudo.png)

Now, save the patched binary.

![new-bin](/assets/ios-jb-detect-bypass/21-patch-bin.png)

Put the patched binary in the application directory on the device replacing the original binary. This patched binary does not have code signing, so for it run successfully, the [AppSync Unified](https://cydia.akemi.ai/?page/net.angelxwind.appsyncunified) Tweak from [Karens Repo](https://cydia.akemi.ai/?) must be installed from Cydia on the Jailbroken device.

#### Bypassing FileSystem Based Checks With Cydia Tweaks

There are several tweaks available in cydia which allows to bypass jailbreak detection. Below are some of the jailbreak detection bypass tweaks which works with different iOS versions.

| Tweak Name | Cydia Repo | iOS Version Support |
| ---------- | ---------- | ------------------- |
| xCon | Available in Cydia Default Repo's (ModMyi)| iOS 9|
| tsProtector 8+ | Available in Cydia Default Repo's (BigBoss)| iOS 8 & 9 |
| JailProtect | [julioverne's Repo](http://julioverne.github.io/) | iOS 10 |
| Shadow| [Jolano's Repo](https://ios.jjolano.me/)| iOS 8.0 - 12.1.2 |
| Liberty Lite | [Ryley's Repo](ryleyangus.com/repo/)| iOS 11 - 12 |
| UnSub | [Nepeta Repo Mirror](http://nepeta.ignition.fun) | iOS 9 - 12|

Lets install and test the Liberty Lite tweak to see whether it is able to bypass our simple jailbreak detection.

![liberty](/assets/ios-jb-detect-bypass/22-liberty.png) | ![liberty_bypass](/assets/ios-jb-detect-bypass/23-liberty-bypass.png)


The Liberty Lite tweak successfully defeats the **Cydia.app** file system check.

### Detection Based on cydia:// URI Scheme

Most of the popular jailbreaks installs the Cydia store application and registers the **cydia://** uri scheme on the device. If an application is able to open a url starting with the **cydia://** uri scheme, the device must be jailbroken.

Let us modify the jailbreak detection to include more file system path checks along with the **cydia://** uri scheme check. The **jbCheck1** method performs file system based checks and **jbCheck2** does the cydia uri scheme check. in both the methods logging is enabled so that we can see the output of each check on the Xcode console during runtime.

![jbchecks](/assets/ios-jb-detect-bypass/24-jbchecks.png)

Modify the code to run when the **isJailbroken** button in ui is clicked to invoke both the checks.

![jbBtnCode](/assets/ios-jb-detect-bypass/25-jbbtncode.png)

Install and run the application on the device and observe the xcode logs.

![xcodelog](/assets/ios-jb-detect-bypass/26-xcodelog.png)

It can be seen that, both the checks were successfull and the app should show the alert stating that the device is jailbroken.

Now let us enable the Liberty Lite Tweak and see if it is able to bypass these checks.

![libertybeat](/assets/ios-jb-detect-bypass/27-xcodelog-liberty.png)

The tweak is able to bypass the cydia:// uri scheme check and most of the file system based checks except for the `/usr/bin/apt` check.


