package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type pciDevice struct {
	addr   string
	vendor string
	id     string
	driver string
	originalDriver string
}

func devDriver(addr string) (string, error) {
	name, err := os.Readlink("/sys/bus/pci/devices/"+addr+"/driver")
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	} else if err != nil {
		return "", err
	} else {
		p := strings.Split(name, "/")
		return p[len(p)-1], nil
	}
}

func bindDev(dev *pciDevice, driver string) error {
	if dev.driver == driver {
		return nil
	}
	if err := unbindDev(dev); err != nil {
		return err
	}
	bind, err := os.OpenFile("/sys/bus/pci/drivers/"+driver+"/bind", os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(bind)
	if _, err := w.WriteString(dev.addr); err != nil {
		bind.Close()
		return err
	}
	if err = w.Flush(); err != nil {
		bind.Close()
		return err
	}
	if err = bind.Close(); err != nil {
		return err
	}
	dev.driver, err = devDriver(dev.addr)
	if err != nil {
		return err
	}
	if dev.driver != driver {
		var msg string
		if dev.driver != "" {
			msg = fmt.Sprintf("bound to %s", dev.driver)
		} else {
			msg = "not bound to any driver"
		}
		return fmt.Errorf("binding %s to %s failed. Currently %s", dev.addr, driver, msg)
	}
	return nil
}

func bindOriginalDriver(dev *pciDevice) error {
	if dev.driver == dev.originalDriver {
		return nil
	}
	if dev.originalDriver == "" {
		return unbindDev(dev)
	}
	return bindDev(dev, dev.originalDriver)
}

func unbindDev(dev *pciDevice) error {
	if dev.driver == "" {
		return nil
	}
	unbind, err := os.OpenFile("/sys/bus/pci/devices/" + dev.addr + "/driver/unbind", os.O_WRONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	w := bufio.NewWriter(unbind)
	if _, err = w.WriteString(dev.addr); err != nil {
		unbind.Close()
		return err
	}
	if err = w.Flush(); err != nil {
		unbind.Close()
		return err
	}
	return unbind.Close()
}

func vfioBindDevice(dev *pciDevice) error {
	if dev.driver == "vfio-pci" {
		fmt.Printf("%s already bound to vfio-pci\n", dev.addr)
		return nil
	}

	if err := unbindDev(dev); err != nil {
		return err
	}

	// TODO modprobe
	v, err := os.OpenFile("/sys/bus/pci/drivers/vfio-pci/new_id", os.O_WRONLY, 0)
	if err != nil {
		bindOriginalDriver(dev)
		return err
	}
	w := bufio.NewWriter(v)
	if _, err = w.WriteString(fmt.Sprintf("%s %s\n", dev.vendor, dev.id)); err != nil {
		v.Close()
		bindOriginalDriver(dev)
		return err
	}
	if err = w.Flush(); err != nil {
		v.Close()
		bindOriginalDriver(dev)
		return err
	}
	if err = v.Close(); err != nil {
		bindOriginalDriver(dev)
		return err
	}

	if dev.driver, err = devDriver(dev.addr); err != nil {
		bindOriginalDriver(dev)
		return err
	}
	if dev.driver == "vfio-pci" {
		return nil
	}
	if dev.driver != "" {
		return fmt.Errorf("%s bound to %s driver after attempting unbind\n", dev.addr, dev.driver)
	}

	fmt.Printf("vfio-pci didn't automatically bind %s. Binding...\n", dev.addr)
	err = bindDev(dev, "vfio-pci")
	if err != nil {
		bindOriginalDriver(dev)
	}
	return err
}

func vfioBind(group []*pciDevice) error {
	for i, dev := range group {
		if err := vfioBindDevice(dev); err != nil {
			for j := 0; j < i; j++ {
				bindOriginalDriver(group[j])
			}
			return err
		}
	}
	return nil
}

func removeDevice(device *pciDevice) error {
	remove, err := os.OpenFile("/sys/bus/pci/devices/" + device.addr + "/remove", os.O_WRONLY, 0)
	if err != nil {
		return err
	}

	if _, err = remove.Write([]byte{'1'}); err != nil {
		remove.Close()
		return err
	}
	return remove.Close()
}

func resetGroup(group []*pciDevice) error {
	var err error
	var tryRescan bool
	for _, dev := range group {
		if err = removeDevice(dev); err != nil {
			break
		}
		tryRescan = true
	}
	if !tryRescan {
		return err
	}

	rescan, err := os.OpenFile("/sys/bus/pci/rescan", os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	if _, err = rescan.Write([]byte{'1'}); err != nil {
		rescan.Close()
		return err
	}
	return rescan.Close()
}

func isEndpoint(addr string) (bool, error) {
	config, err := os.Open("/sys/bus/pci/devices/" + addr + "/config")
	if err != nil {
		return false, err
	}

	headerType := make([]byte, 1)
	// see PCI spec or pci_setup_device() in drivers/pci/probe.c
	if _, err := config.ReadAt(headerType, 0x0e); err != nil {
		config.Close()
		return false, err
	}
	ret := headerType[0]&0x7f == 0
	return ret, config.Close()
}

func newPCIDevice(addr string) (*pciDevice, error) {
	ret := &pciDevice{addr: addr}
	vendor, err := os.OpenFile("/sys/bus/pci/devices/"+addr+"/vendor", os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}

	ret.vendor, err = bufio.NewReader(vendor).ReadString('\n')
	if err != nil {
		vendor.Close()
		return nil, err
	}
	ret.vendor = strings.TrimSpace(ret.vendor)
	if err = vendor.Close(); err != nil {
		return nil, err
	}

	id, err := os.OpenFile("/sys/bus/pci/devices/"+addr+"/device", os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	ret.id, err = bufio.NewReader(id).ReadString('\n')
	if err != nil {
		id.Close()
		return nil, err
	}
	ret.id = strings.TrimSpace(ret.id)
	if err = id.Close(); err != nil {
		return nil, err
	}

	if ret.driver, err = devDriver(ret.addr); err != nil {
		return nil, err
	}
	ret.originalDriver = ret.driver
	return ret, nil
}

func checkSafety(group []*pciDevice) bool {
	// TODO
	return true
}

func iommuGroup(dev *pciDevice) ([]*pciDevice, error) {
	var ret []*pciDevice

	ret = append(ret, dev)
	group, err := os.Open("/sys/bus/pci/devices/" + dev.addr + "/iommu_group/devices")
	if err != nil {
		return nil, err
	}
	dents, err := group.Readdir(-1)
	if err != nil {
		group.Close()
		return nil, err
	}
	for _, info := range dents {
		if dev.addr == info.Name() {
			continue
		}
		endpoint, err := isEndpoint(info.Name())
		if err != nil {
			return nil, err
		}
		if !endpoint {
			continue
		}
		device, err := newPCIDevice(info.Name())
		if err != nil {
			return nil, err
		}
		ret = append(ret, device)
	}
	return ret, group.Close()
}

func devFromInterface(id string) (*pciDevice, error) {
	return nil, nil
}

func devFromID(id string) (*pciDevice, error) {
	return nil, nil
}

var addrRE = regexp.MustCompile(`([0-9a-fA-F]{4}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])`)

func devFromAddr(addr string) (*pciDevice, error) {
	s := addrRE.FindStringSubmatch(addr)
	if s == nil {
		return nil, nil
	}

	device := s[3]
	id, err := strconv.ParseInt(device, 16, 8)
	if err != nil {
		return nil, err
	}
	if id > 0x1f {
		return nil, fmt.Errorf("device ID %s in (PCI address?) %s should not be > 0x1f\n", device, addr)
	}
	_, err = os.Stat("/sys/bus/pci/devices/" + addr)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("PCI device %s not found", addr)
	}
	if err != nil {
		return nil, err
	}
	return newPCIDevice(addr)
}

var (
	group = flag.Bool("group", false, "On reset, remove and rescan each argument's IOMMU group (non-bridge devices only) if true.\nOtherwise only the arguments themselves.")
)

func main() {
	flag.Parse()

	args := flag.Args()
	logger := log.New(os.Stderr, os.Args[0]+": ", 0)

	if len(args) < 1 {
		logger.Fatalf("%s [PCI addr | (PCI vendor:PCI device) | network interface]\n", os.Args[0])
	}

	// TODO remove ugliness and use subcommands package
	var arg string
	if args[0] == "reset" {
		arg = args[1]
	} else {
		arg = args[0]
	}

	var device *pciDevice
	var err error

	if device, err = devFromAddr(arg); err != nil {
		logger.Fatal(err)
	}
	if device == nil {
		if device, err = devFromID(arg); err != nil {
			logger.Fatal(err)
		}
	}
	if device == nil {
		if device, err = devFromInterface(arg); err != nil {
			logger.Fatal(err)
		}
	}
	if device == nil {
		logger.Fatalf("Could not parse %s Please give one of:\n"+
			"\tPCI Address (e.g. 0000:01:00.1)\n"+
			"\tPCI vendor/device pair (e.g. 1022:145f)\n"+
			"\tNetwork Interface (e.g. eth0)\n", arg)
	}

	var group []*pciDevice
	if group, err = iommuGroup(device); err != nil {
		logger.Fatal(err)
	}

	if args[0] == "reset" {
		if err = resetGroup(group); err != nil {
			logger.Fatal(err)
		}
		os.Exit(0)
	}
	if !checkSafety(group) {
		os.Exit(0)
	}
	if err = vfioBind(group); err != nil {
		logger.Fatal(err)
	}
}
