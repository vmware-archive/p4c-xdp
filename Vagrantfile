# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|
  # The most common configuration options are documented and commented below.
  # For a complete reference, please see the online documentation at
  # https://docs.vagrantup.com.

  config.vm.box = "ubuntu/xenial64"

  # Disable automatic box update checking. If you disable this, then
  # boxes will only be checked for updates when the user runs
  # `vagrant box outdated`. This is not recommended.
  config.vm.box_check_update = false
  config.vm.provision "shell", inline: <<-SHELL
      sudo apt-get update
      sudo apt-get install -y build-essential dpkg

    # get the kernel 4.10.0-rc8 because we need newer kernel's BPF verifier
      wget http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.10-rc8/linux-image-4.10.0-041000rc8-generic_4.10.0-041000rc8.201702121731_amd64.deb
      dpkg -i linux-image-4.10.0-041000rc8-generic_4.10.0-041000rc8.201702121731_amd64.deb 
      wget http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.10-rc8/linux-headers-4.10.0-041000rc8_4.10.0-041000rc8.201702121731_all.deb
      dpkg -i linux-headers-4.10.0-041000rc8_4.10.0-041000rc8.201702121731_all.deb
    
      # Fetch the p4xdp docker image
      apt-get install -y docker.io
      docker pull u9012063/p4xdp
  SHELL
  # reboot to the newer kernel
  config.vm.provision :reload
end

