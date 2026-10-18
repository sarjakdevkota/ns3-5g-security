NS3 and 5G-LENA installation

##install dependencies##

sudo apt-get update
sudo apt install git g++ python3 python3-dev pkg-config sqlite3 qtbase5-dev
sudo apt install libc6-dev
sudo apt install sqlite
sudo apt install cmake

#clone ns3 and 5G LENA##

git clone https://gitlab.com/nsnam/ns-3-dev.git
go to contrib or src. I am choosing contrib
cd ns-3-dev/contrib
git clone https://gitlab.com/cttc-lena/nr.git
cd nr/

###checkout the latest branch###

git checkout 5g-lena-v2.5.y

###for nr check which is compatible###
cd contrib/nr

cat RELEASE_NOTES.md | grep "Recommended ns-3 release"

###check ns3 branch (for 5g-lena-v2.5.y ns-3.39)###

git checkout ns-3.39
./ns3 clean
./ns3 configure --enable-examples --enable-test
./ns3 build



https://www.nsnam.org/docs/models/html/lte-user.html#basic-simulation-program

./ns3 run cttc-nr-demo