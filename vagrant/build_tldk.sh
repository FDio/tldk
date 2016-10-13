export RTE_TARGET=x86_64-native-linuxapp-gcc
export RTE_SDK=/home/vagrant/dpdk/

# Get code
git clone http://dpdk.org/git/dpdk

# Build code
cd dpdk
make config T=${RTE_TARGET}
make

# Install kernel modules
sudo modprobe uio
sudo insmod build/kmod/igb_uio.ko

# Configure hugepages
echo 1024 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
sudo mkdir /mnt/huge
sudo mount -t hugetlbfs nodev /mnt/huge

ln -s ${RTE_SDK}/build ${RTE_SDK}/${RTE_TARGET}

cd /tldk

make all

cd
