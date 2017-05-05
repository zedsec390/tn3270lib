# TN3270 Python Library (BETA)

This library is a pure python implemnation of a TN3270e emulator. To test this library you can issue the command `python tn3270lib.py <hostname> <port>`.

This library also implements  IND$FILE file transfering. 

To connect to a mainframe and log on:

```
>>> import tn3270lib
>>> tn3270 = tn3270lib.TN3270()
>>> host = "192.168.32.70"
>>> port = 23
>>> tn3270.initiate(host, port)
True
>>> data = tn3270.get_screen()
>>> print data
z/OS V1R13 PUT Level 1209                          IP Address = 10.10.0.13
                                                   VTAM Terminal =

                        Application Developer System
                                 //  OOOOOOO   SSSSS
                               //  OO    OO SS
                       zzzzzz //  OO    OO SS
                         zz  //  OO    OO SSSS
                       zz   //  OO    OO      SS
                     zz    //  OO    OO      SS
                   zzzzzz //   OOOOOOO  SSSS

                   System Customization - ADCD.Z113H.*



 ===> Enter "LOGON" followed by the TSO userid. Example "LOGON IBMUSER" or
 ===> Enter L followed by the APPLID
 ===> Examples: "L TSO", "L CICSTS41", "L CICSTS42", "L IMS11", "L IMS12"
>>> tn3270.send_cursor("TSO")
>>> tn3270.get_all_data()
>>> tn3270.send_cursor("margo")
>>> tn3270.get_all_data()
>>> tn3270.send_cursor("secret")
>>> tn3270.get_all_data()
>>> data = tn3270.get_screen()
>>> print data
ICH70001I PLAGUE   LAST ACCESS AT 12:15:24 ON TUESDAY, SEPTEMBER 13, 2016       
IKJ56455I PLAGUE LOGON IN PROGRESS AT 12:17:25 ON SEPTEMBER 13, 2016            
IKJ56951I NO BROADCAST MESSAGES                                                 
*****************************************************************               
*                                                               *               
*     WELCOME TO                                #               *               
*                                               ##              *               
* #######  ######## ########   ###### #######   ###  ##         *               
*  ###  ##  ###      ###      ###      ##   ##  #### ##         *               
*  ###  ##  #######  #######  ###      ##   ##  #######         *               
*  ###  ##  ###      ##       ###      ##   ##  ### ###         *               
*  ######   #######  ##        ######   #####   ###  ##         *               
*                                                     #         *               
*                                                               *               
*                                         A B.U.M. MAINFRAME    *               
*****************************************************************               
                                                                                
READY                                                                           
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                

>>> 
```

## Debugging

To help understand all the tn3270 commands and the various stages of the connection debugging is included with this library. To enable simple debugging use `tn3270.set_debuglevel(1)` to increase the verbosity you can set debugging to level 2 `tn3270.set_debuglevel(2)` but it explains every tn3270 command and push to the buffer but can aid in understanding what it happening behind the scenes.

## LU Setting

This library also supports selecting a specific LU. Use the function `set_LU("LUNAME")` to set the LU you want to use priot to initiating a connection.

## File Transfer

With this library you can now send and receive files/datasets EBCDIC to ASCII translation is done by z/OS if you use the get/send_ascii functions

To send file you use the methods `send_ascii_file`/`send_binary_file`. Note that each method requires a destination dataset and a local file you wish to send.

```
>>> tn3270.send_ascii_file("'ibmuser.jcltest'","/home/dade/awesome.jcl")
>>> tn3270.send_binary_file("'ibmuser.exec'","/home/dade/a.out")
```

To receive files you can use the methods  `get_ascii_file`/`get_binary_file`. As with sending a file you establish the from dataset and the file you wish to save to locally:

```
>>> tn3270.get_ascii_file("'ibmuser.jcltest'","/home/dade/new.jcl")
>>> tn3270.get_binary_file("'ibmuser.asm(compiled)'","/home/dade/compiled.asm")
```

## Thanks

This library wouldn't have been possible with x3270 and its great `-trace` feature, RFC 2355, RFC 1576, the python telnet library and various stackoverflow tips!
