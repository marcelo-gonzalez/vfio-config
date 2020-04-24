package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/subcommands"
)

type pciDevice struct {
	addr           string
	vendor         string
	id             string
	driver         string
	originalDriver string
}

func devRecordDriver(dev *pciDevice) error {
	name, err := os.Readlink("/sys/bus/pci/devices/" + dev.addr + "/driver")
	if errors.Is(err, os.ErrNotExist) {
		dev.driver = ""
		return nil
	}
	if err != nil {
		return err
	}
	p := strings.Split(name, "/")
	dev.driver = p[len(p)-1]
	return nil
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
	if err = devRecordDriver(dev); err != nil {
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
	fmt.Printf("Bound %s to %s\n", dev.addr, dev.driver)
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
	unbind, err := os.OpenFile("/sys/bus/pci/devices/"+dev.addr+"/driver/unbind", os.O_WRONLY, 0)
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
	if err = unbind.Close(); err != nil {
		return err
	}
	return devRecordDriver(dev)
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

	if err = devRecordDriver(dev); err != nil {
		bindOriginalDriver(dev)
		return err
	}
	if dev.driver == "vfio-pci" {
		fmt.Printf("%s now bound to vfio-pci\n", dev.addr)
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
	remove, err := os.OpenFile("/sys/bus/pci/devices/"+device.addr+"/remove", os.O_WRONLY, 0)
	if err != nil {
		return err
	}

	if _, err = remove.Write([]byte{'1'}); err != nil {
		remove.Close()
		return err
	}
	fmt.Printf("Removed %s\n", device.addr)
	return remove.Close()
}

func rescan() error {
	r, err := os.OpenFile("/sys/bus/pci/rescan", os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	if _, err = r.Write([]byte{'1'}); err != nil {
		r.Close()
		return err
	}
	if err = r.Close(); err != nil {
		return err
	}
	fmt.Println("Issued PCI bus rescan")
	return nil
}

func reset(group []*pciDevice) error {
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
	return rescan()
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
	return headerType[0]&0x7f == 0, config.Close()
}

func readString(path string) (string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return "", err
	}

	str, err := bufio.NewReader(f).ReadString('\n')
	if err != nil {
		f.Close()
		return "", err
	}
	return strings.TrimSpace(str), f.Close()
}

func newPCIDevice(addr string) (*pciDevice, error) {
	var err error
	ret := &pciDevice{addr: addr}

	ret.vendor, err = readString("/sys/bus/pci/devices/" + addr + "/vendor")
	if err != nil {
		return nil, err
	}
	ret.id, err = readString("/sys/bus/pci/devices/" + addr + "/device")
	if err != nil {
		return nil, err
	}

	if err = devRecordDriver(ret); err != nil {
		return nil, err
	}
	ret.originalDriver = ret.driver
	return ret, nil
}

func checkSafety(group []*pciDevice) (bool, error) {
	devMounts := make(map[string]string)
	mounts, err := os.Open("/proc/mounts")
	if err != nil {
		return false, err
	}
	r := bufio.NewReader(mounts)
	for {
		m, err := r.ReadString('\n')
		if errors.Is(err, io.EOF) {
			if err = mounts.Close(); err != nil {
				return false, err
			}
			break
		}
		if err != nil {
			mounts.Close()
			return false, err
		}
		f := strings.Fields(m)
		d := strings.Split(f[0], "/")
		if len(d) < 3 {
			continue
		}
		if d[1] != "dev" {
			continue
		}
		if len(f) < 2 {
			devMounts[d[2]] = "<mountpoint unknown?>"
		} else {
			devMounts[d[2]] = f[1]
		}
	}

	// Is it true that /dev/foo will always appear as
	// foo in /sys/class/block ? Maybe no... should check
	block, err := os.Open("/sys/class/block")
	if err != nil {
		return false, err
	}
	dents, err := block.Readdir(-1)
	if err != nil {
		block.Close()
		return false, err
	}
	if err = block.Close(); err != nil {
		return false, err
	}
	wouldNuke := make(map[string][]string)
	for _, dent := range dents {
		if _, ok := devMounts[dent.Name()]; !ok {
			continue
		}
		path, err := filepath.EvalSymlinks("/sys/class/block/" + dent.Name())
		if err != nil {
			return false, err
		}
		t := strings.Split(path, "/")
		for _, c := range t {
			for _, dev := range group {
				if dev.addr == c {
					s := wouldNuke[dev.addr]
					if s == nil {
						wouldNuke[dev.addr] = []string{dent.Name()}
					} else {
						s = append(s, dent.Name())
						wouldNuke[dev.addr] = s
					}
				}
			}
		}
	}
	if len(wouldNuke) == 0 {
		return true, nil
	}

	fmt.Println("The following devices would be unbound, but are backing a mount:\n")
	for k, v := range wouldNuke {
		for _, dev := range v {
			fmt.Printf("%s => %s\n", k, devMounts[dev])
		}
	}
	fmt.Println("\nYou probably don't want to do that. Continue anyway [yes/no]?")
	s := bufio.NewScanner(os.Stdin)
	for s.Scan() {
		if s.Text() != "yes" && s.Text() != "no" {
			fmt.Println("Please say \"yes\" or \"no\"")
			continue
		}
		return s.Text() == "yes", nil
	}
	// TODO: think of other dangerous stuff
	return false, nil
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

func devFromInterface(ifc string) (*pciDevice, error) {
	if _, err := os.Stat("/sys/class/net/" + ifc); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if _, err := os.Stat("/sys/class/net/" + ifc + "/device"); errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%s doesn't seem to be backed by a real device", ifc)
	} else if err != nil {
		return nil, err
	}
	d, err := os.Readlink("/sys/class/net/" + ifc + "/device")
	if err != nil {
		return nil, err
	}
	p := strings.Split(d, "/")
	fmt.Printf("%s => %s\n", ifc, p[len(p)-1])
	return newPCIDevice(p[len(p)-1])
}

var vidRE = regexp.MustCompile(`^(?:0x)?([0-9a-f]{4}):(?:0x)?([0-9a-f]{4})$`)

func devsFromID(vid string) ([]*pciDevice, error) {
	s := vidRE.FindStringSubmatch(vid)
	if s == nil {
		return nil, nil
	}
	vendor, err := strconv.ParseUint(s[1], 16, 16)
	if err != nil {
		return nil, err
	}
	device, err := strconv.ParseUint(s[2], 16, 16)
	if err != nil {
		return nil, err
	}

	devs, err := os.Open("/sys/bus/pci/devices")
	if err != nil {
		return nil, err
	}
	dents, err := devs.Readdir(-1)
	if err != nil {
		return nil, err
	}
	var ret []*pciDevice
	for _, d := range dents {
		v, err := readString("/sys/bus/pci/devices/" + d.Name() + "/vendor")
		if errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, err
		}
		vd, err := strconv.ParseUint(v, 0, 16)
		if err != nil {
			return nil, err
		}
		if vd != vendor {
			continue
		}
		dev, err := readString("/sys/bus/pci/devices/" + d.Name() + "/device")
		if errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, err
		}
		dv, err := strconv.ParseUint(dev, 0, 16)
		if err != nil {
			return nil, err
		}
		if dv != device {
			continue
		}
		fmt.Printf("%s => %s\n", vid, d.Name())
		match := &pciDevice{addr: d.Name(), vendor: v, id: dev}
		if err = devRecordDriver(match); err != nil {
			return nil, err
		}
		match.originalDriver = match.driver
		ret = append(ret, match)
	}
	if ret == nil {
		return nil, fmt.Errorf("vendor/device pair %s not found", vid)
	}
	return ret, nil
}

var addrRE = regexp.MustCompile(`^([0-9a-fA-F]{4}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])$`)

func devFromAddr(addr string) (*pciDevice, error) {
	s := addrRE.FindStringSubmatch(addr)
	if s == nil {
		return nil, nil
	}

	device := s[3]
	id, err := strconv.ParseUint(device, 16, 8)
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

func execute(f func([]*pciDevice) error, args []string, wholeGroup bool) subcommands.ExitStatus {
	devices := make([]*pciDevice, 0, len(args))
	var err error

	appendUnique := func(devices []*pciDevice, devs ...*pciDevice) ([]*pciDevice, error) {
		for _, dev := range devs {
			unique := true
			for _, d := range devices {
				if d.addr == dev.addr {
					unique = false
					break
				}
			}
			if unique {
				var ds []*pciDevice
				if wholeGroup {
					ds, err = iommuGroup(dev)
					if err != nil {
						return nil, err
					}
				} else {
					ds = []*pciDevice{dev}
				}
				devices = append(devices, ds...)
			}
		}
		return devices, nil
	}

	for _, arg := range args {
		var device *pciDevice
		if device, err = devFromAddr(arg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return subcommands.ExitFailure
		}
		if device != nil {
			devices, err = appendUnique(devices, device)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return subcommands.ExitFailure
			}
			continue
		}

		var devs []*pciDevice
		if devs, err = devsFromID(arg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return subcommands.ExitFailure
		}
		if devs != nil {
			devices, err = appendUnique(devices, devs...)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return subcommands.ExitFailure
			}
			continue
		}

		if device, err = devFromInterface(arg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return subcommands.ExitFailure
		}
		if device != nil {
			devices, err = appendUnique(devices, device)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return subcommands.ExitFailure
			}
			continue
		} else {
			fmt.Fprintf(os.Stderr, "Could not parse device %s.\n", arg)
			return subcommands.ExitFailure
		}
	}
	safe, err := checkSafety(devices)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return subcommands.ExitFailure
	}
	if !safe {
		return subcommands.ExitSuccess
	}
	if err = f(devices); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

var deviceFmtDesc = "Where each [device] is one of:\n" +
	"\tPCI Address (e.g. 0000:01:00.1)\n" +
	"\tPCI vendor/device pair (e.g. 1022:145f)\n"

type bindCmd struct{}

func (*bindCmd) Name() string     { return "bind" }
func (*bindCmd) Synopsis() string { return "Bind a PCI device's IOMMU group to the VFIO driver" }
func (*bindCmd) Usage() string {
	return fmt.Sprintf("bind [devices...]\n%s\tNetwork Interface (e.g. eth0)\n", deviceFmtDesc)
}

func (*bindCmd) SetFlags(*flag.FlagSet) {}

func (b *bindCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if f.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "%s", b.Usage())
		return subcommands.ExitUsageError
	}
	return execute(vfioBind, f.Args(), true)
}

type resetCmd struct {
	wholeGroup bool
}

func (*resetCmd) Name() string     { return "reset" }
func (*resetCmd) Synopsis() string { return "Remove PCI devices and issue a rescan" }
func (*resetCmd) Usage() string {
	return fmt.Sprintf("reset [--group] [devices...]\n%s", deviceFmtDesc)
}
func (r *resetCmd) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&r.wholeGroup, "group", false,
		"On reset, remove and rescan each argument's whole IOMMU group\n(non-bridge devices only) if true. Otherwise\nonly the specified devices.")
}

func (r *resetCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if f.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "%s", r.Usage())
		return subcommands.ExitUsageError
	}
	return execute(reset, f.Args(), r.wholeGroup)
}

func main() {
	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.FlagsCommand(), "")
	subcommands.Register(subcommands.CommandsCommand(), "")
	subcommands.Register(&bindCmd{}, "")
	subcommands.Register(&resetCmd{}, "")

	flag.Parse()
	os.Exit(int(subcommands.Execute(context.Background())))
}
