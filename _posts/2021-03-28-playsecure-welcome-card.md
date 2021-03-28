---
layout: post
title: Playsecure CTF 2021 - Welcome Card
---
### Challenge Description

Just a welcome card generator website. Nothing vulnerable here! Some characters are filtered to prevent exploitation. Good luck!
The flag is well...somewhere. Find it on the system! It's still called flag.txt.

Challenge: http://web.ps.ctf.ae:8882/

<!-- more -->

### Recon

Interacting with the web application to understand its functionality. The web app provides a welcome card generator form.

![wc00](/assets/playsecure2021/wc00.png)

Filling in all required fields and submitting the form, we get a welcome card.

![wc01](/assets/playsecure2021/wc01.png)

### Testing for Template Injection

Injecting basic template injection payloads such as  `{{9*9}}`.

![wc02](/assets/playsecure2021/wc02.png)

We see that the description field is vulnerable to SSTI. 

![wc03](/assets/playsecure2021/wc03.png)

Reproducing the same using burp repeater.

![wc04](/assets/playsecure2021/wc04.png)

1. Submitting <pre><code>{{3*3}}</code></pre> in desc parameter.
2. We get 9 in response.

The desc POST parameter is vulnerable to SSTI.

### Identifying Template Engine

We use the methodology specified here: [Template Engine Identification](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#methodology)

![wc05](/assets/playsecure2021/wc05.png)

1. Submitting `{{3*'3'}}` in desc.
2. Return 333 in response

Indicated Jinja2 Templating Engine.

### Jinja2 Basic Injection

Basic injection payloads for Jinja2 can be found in [PayloadAllThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2---basic-injection)

![wc06](/assets/playsecure2021/wc06.png)

We can retrieve config.items() to verify Jinja2 is in use.

![wc07](/assets/playsecure2021/wc07.png)

Trying different payloads for Jinja2 yeilds no results as mentioned in challenge description some characters are filtered.

![wc08](/assets/playsecure2021/wc08.png)

![wc09](/assets/playsecure2021/wc09.png)

All these attempts results in internal server error.

### Filter Evasion

Attempting to build payload from scratch we inject `{{''.__class__}}`.

![wc10](/assets/playsecure2021/wc10.png)

1. Inject `{{''.__class__}}`
2. No response.

Ideal response would be str class. Instead we got empty response. This might indicate that underscore in the desc param might be filtered.

We can avoid using underscore `_` in desc parameter by defining a new GET parameter and putting the string with underscore as value of this parameter. The GET parameter value can then be accessed as `request.args.param_name`. 

**Retrieving str class.**

![wc11](/assets/playsecure2021/wc11.png)

**Retrieving Method Resolution Order of str Class**

![wc12](/assets/playsecure2021/wc12.png)

At index 1 of the MRO (method resolution order), we have the `<class 'object'>`.

**Retrieving The index 1 of MRO**

 We can use `__getitem__` method to access objects at different index of list.

![wc13](/assets/playsecure2021/wc13.png)

Now we have the `<class 'object'>`.

**Getting the subclasses**

![wc14](/assets/playsecure2021/wc14.png)

**Finding Index of subprocess.Popen**

subprocess.Popen is of interest to us as it would allow us to run system commands. This is located at 411 index in subclasses list.

![wc15](/assets/playsecure2021/wc15.png)

subprocess.Popen

![wc16](/assets/playsecure2021/wc16.png)


**Remote Code Execution**

![wc17](/assets/playsecure2021/wc17.png)

Shows the output of `ls /` command.

### Finding and Retrieving the Flag

Searching for flag.txt:

![wc18](/assets/playsecure2021/wc18.png)

Flag is at **/opt/flag.txt**

Getting flag contents:

![wc19](/assets/playsecure2021/wc19.png)


*FLAG: CTFAE{ASurpriseToBeSureButAWelcomeOne}*
