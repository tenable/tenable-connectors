# -*- mode: ruby -*-
# vi: set ft=ruby :
Vagrant.configure("2") do |config|
  #config.vm.box = "bento/rockylinux-9"
  config.vm.box = "generic/alma9"
  config.vm.network "forwarded_port", guest: 9090, host: 9090
  config.vm.synced_folder ".", "/vagrant", disabled: true
  config.vm.box_check_update = true

  config.vm.provider "virtualbox" do |vb|
    vb.memory = "4096"
    vb.gui = true
  end
  config.vm.provider "parallels" do |pl|
    pl.memory = "4096"
  end
  config.vm.provider "vmware_desktop" do |vmw|
    vmw.vmx['memsize'] = "4096"
    vmw.gui = true
  end
  config.vm.provider "qemu" do |qemu|
    qemu.memory = 4096
  end

  config.vm.provision "shell", inline: <<-SHELL
     dnf -y install https://tenable-appliance-repo.s3.us-east-1.amazonaws.com/ecosystem/el/tif-repo-installer.rpm
     dnf -y install tif
     echo "" > /etc/cockpit/disallowed-users
     export ROOT_PW=$(date +%s | sha256sum | base64 | head -c 32)
     echo "root password is set to '${ROOT_PW}'"
     chpasswd <<<"root:$ROOT_PW"
  SHELL
end
