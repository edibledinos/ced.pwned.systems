Title: web300 - Jamie's Chef Layers
Date: 2016-05-31 19:13
Author: doskop
Tags: CTF

## Introduction

> It appears this system holds a secret recipe from top chef Jamie,
> but it can only beaccessed by himself. Can you find a way to get to
> it? http://145.111.225.36
>
> No bruteforcing is required.

Download the web app's source [here]({filename}/downloads/hitb-2016-ctf/web300/release-1.02.tgz).

## Analysis

Another web challenge based on the Phalcon framework (just like last year's teaser [SATCOM]({filename}/HiTB 2015 Teaser CTF/web1000 - SATCOM.md)).

Let's see what we've got. We are presented with a log-in screen, so let's try to log in. Click the forgot password link and you're presented with a hint that the administrator **dave** can create a login token for you. Let's see what we can find.

If you look at the source of the login page, you'll see this comment:

    :::html
    <!-- release-1.02.tgz -->

That looks like the filename of the latest release tarball of the the web application. Let's see if we can download it. Again, look in the source of the login page and you'll notice this CSS include:

	:::html
    <link href="/media/view/style.css" rel="stylesheet" type="text/css"/>

If you open that link, you'll see it starts with a header that contains the current time so it's probably dynamically generated. Try to use that to get the mysterious release-1.02.tgz file: http://145.111.225.36/media/view/release-1.02.tgz

You'll get an error message that you need to be authenticated. But that's what we're trying to crack. Let's see how well-protected this particular view is:

	:::bash
    curl -H"Authenticated: yes" http://145.111.225.36/media/view/release-1.02.tgz

Silly but conveniently, we now have the source in the form of a tarball. Except that it starts we a text header, so remove that before extracting it (don't use nano, it'll end up destroying the file because it tries to fix carriage returns or line feeds).

## Exploitation

Ok, so let's look for that authentication token generator. Don't look too hard, it's in *www/app/util/user/AccessTokenHelper.php*:

    :::php
    <?php
    
    namespace hitb\util\user;

    class AccessTokenHelper
    {
        /**
         * Very very safe token generation.
         *
         * @param $user
         * @return string
         */
        public static function getAccessTokenForUser($user) {
            $data = base64_encode($user->uid . strrev($user->uid));
            $res = '';
            for ($i = 0; $i < strlen($data); $i++){
                $res .= dechex(ord($data[$i]));
            }
            return $res;
        }
    }

Very very safe token generation indeed. Concatenate the login name with its reverse, base64 encode that and turn each byte of the result in a hexadecimal representation. Let's use pwnypack to generate a token for the user *dave*:

    :::python
    def make_token(uid):
        return enhex(enb64(uid + uid[::-1]))
	print(make_token('dave'))


Ok, now log in using the username *dave* and the generated token. We're now one step closer but unfortunately Dave doesn't have a high enough access level to read the secret recipe. Only Jamie does. And that level is so high, that you can't login using the password reset / token method (from *www/app/core/security/DefaultAuthenticationService.php*):

	:::php
    <?php
    // Our moderator can allow employees to login using an access token
    if ($user->guest != 1 &&
    	$user->level < 10 &&
        $user->reset = 1 &&
        $pwd == AccessTokenHelper::getAccessTokenForUser($user)) {
        return $user;
    }

So what **can** we do? Well, as it turns out, we can create guest users which always have a level of 1. However, the `updateGuestUser` function in _www/app/facades/user/DefaultUserFacade.php_ that is used to update the properties of a guest doesn't check what properties are set because the `convertExisting` converter in _www/app/facades/user/converter/UserConverter.php_ just copies all properties from the new user to the existing one. And even better, `updateGuestUser` in _www/app/storefront/controllers/UserController.php_ doesn't do any checks either because `createData` just copies all data from the form which is created from the posted data and calls the user facade's `updateGuestUser` function. That `UserForm` class, contains all the properties of the guest user class: `uid`, `level`, `reset` and `restaurant`. Long story short: The update profile function allows us to set any property of the guest user.

So how do we use this? Create a guest user and use it to log in. Then, go to the update guest profile link (`/user/update`), manipulate the form to include the `level` field and set it to `10`. Then submit the form. You can of course also use curl (get the session id from the browser):

    :::bash
    curl -XPOST -bPHPSESSID=blablabla -dlevel=10 http://145.111.225.36/user/update

Now, go to the recipe page and you'll find your flag!
