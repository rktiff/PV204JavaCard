Application
--------------------------
Universal Password Manager

Original Source Code is available at
--------------------------
http://upm.sourceforge.net

Version
--------------------------
1.14

Thanks 
--------------------------
Adrian Smith

Overview:
--------------------------
The Universal Password Manager(UPM) is free software. The application allows someone to store usernames, passwords, URLs and generic notes in an encrypted database protected by one master password.

Basically, it is generating the key with the help of Password Based Key Derivation Function (PBKDF) using salt and Hash.

As a part of project work for PV-204 Security Technologies, we have integrated the UPM code with Java card. 
Here, we are securing the key by generating and storing encryption key on the trusted platform (Java Card). 
Further, the communication between UPM (running on PC) and Java Card is established over secure channel. 

Development
--------------------------
The development activity was carried out using NetBeans IDE8.1 over Ubuntu 16.4 OS.
The real card "Gemalto USB Shell Token" was utilized.

The contributors
--------------------------
1. Ananya Chatterjee, UCO:459203
2. Rajesh Kumar, UCO:459195
3. Rajesh Chandrakant Mehta, UCO:459194

History
--------------------------
1.0 The original source code cloned and uploaded on github.
The changes made to original application code in the following order:
	1.1 The generation and storing of encryption key was shifted to JavaCard simulation environment. Subsequently, the database managment of original application was modified. The extraction of encryption key from Java Card to PC was added.
	1.2 The above activities were integrated and interfaced with Real Java Card.
	1.3 The Development of secure channel was executed for above communication.
	1.4 Interface of secure channel with Real Java Card was added.
	1.5 Final Version with proper documentation and working code.
		
How To Execute the Code:
--------------------------
1. Install simpleapplet.cap file to the Java Card with following command.
   Command: java -jar gp.jar -install simpleapplet.cap -d
2. Open the project in NetBeans IDE.
3. Run the project.
4. Select the Database -> New Database. Open the file.
5. Enter the master password and follow the instructions.
6. Wait approx. 15 seconds. This is because of generation key on the card.
7. Follow the instruction. Now Your New Database is ready. 
8. Add Account. Account -> Add Account. Follow the instructions.
9. Open Database. Database -> Open Database, browse to existing/newly created database.
10. Enter the master password. Note: More than three failed consecutive attempt will lead you to exit the application. 
11. Wait approx. 15 seconds after entering password.
12. Check the added account details.

Path:
--------------------------
Java Card Application code:
Project-Code/src/JavaCardApplet/SimpleApplet.java

PC-Based application code:
Project-Code/src/upm/JavaCardMngr/PCSideCardInterface.java
Project-Code/src/upm/JavaCardMngr/CardMngr.java
