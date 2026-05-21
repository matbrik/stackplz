package module

import (
    "bytes"
    "context"
    "errors"
    "fmt"
    "io/ioutil"
    "log"
    "math"
    "path/filepath"
    "stackplz/assets"
    "stackplz/user/argtype"
    "stackplz/user/config"
    "stackplz/user/event"
    "stackplz/user/util"
    "strings"
    "time"
    "unsafe"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/btf"
    manager "github.com/ehids/ebpfmanager"
    "golang.org/x/sys/unix"
)

type MStack struct {
    Module
    bpfManager        *manager.Manager
    bpfManagerOptions manager.Options
    eventFuncMaps     map[*ebpf.Map]event.IEventStruct
    eventMaps         []*ebpf.Map

    hookBpfFile string
}

const stackUprobeUID = "stack_uprobe"

func (this *MStack) Init(ctx context.Context, logger *log.Logger, conf config.IConfig) error {
    this.Module.Init(ctx, logger, conf)
    this.Module.SetChild(this)
    this.eventMaps = make([]*ebpf.Map, 0, 2)
    this.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)
    this.hookBpfFile = "stack.o"
    return nil
}

func (this *MStack) GetConf() config.IConfig {
    return this.mconf
}

func (this *MStack) setupManager() error {
    maps := []*manager.Map{}
    probes := []*manager.Probe{}

    events_map := &manager.Map{
        Name: "events",
    }
    maps = append(maps, events_map)

    fork_probe := &manager.Probe{
        Section:      "raw_tracepoint/sched_process_fork",
        EbpfFuncName: "tracepoint__sched__sched_process_fork",
    }
    probes = append(probes, fork_probe)

    for i, uprobe_point := range this.mconf.StackUprobeConf.Points {
        if len(uprobe_point.PointArgs) > 0 {
            return fmt.Errorf("mass uprobe mode supports empty params only; point %d (%s) has %d params", i, uprobe_point.Name, len(uprobe_point.PointArgs))
        }
        this.logger.Printf("idx:%d %s", i, uprobe_point.String())
        if i > 0 {
            continue
        }
        probes = append(probes, this.buildStackProbe(uprobe_point, stackUprobeUID))
    }
    this.logStackConfigSummary()

    this.bpfManager = &manager.Manager{
        Probes: probes,
        Maps:   maps,
    }
    return nil
}

func (this *MStack) buildStackProbe(uprobe_point *config.UprobeArgs, uid string) *manager.Probe {
    sym := uprobe_point.Symbol
    stack_probe := &manager.Probe{
        UID:              uid,
        Section:          "uprobe/stack",
        EbpfFuncName:     "probe_stack",
        AttachToFuncName: sym,
        RealFilePath:     uprobe_point.RealFilePath,
        BinaryPath:       uprobe_point.LibPath,
        NonElfOffset:     uprobe_point.NonElfOffset,
    }

    if sym == "" {
        stack_probe.AttachToFuncName = util.RandStringBytes(8)
        // 这个是相对于库文件基址的偏移
        stack_probe.UAddress = uprobe_point.Offset
    } else {
        // 这个是相对于符号的偏移
        stack_probe.UprobeOffset = uprobe_point.Offset
    }
    return stack_probe
}

func (this *MStack) shouldLogStackPoint(idx int, total int) bool {
    return idx < 5 || idx >= total-5 || idx%256 == 0
}

func (this *MStack) logStackConfigSummary() {
    points := this.mconf.StackUprobeConf.Points
    if len(points) == 0 {
        return
    }
    first := points[0]
    last := points[len(points)-1]
    this.logger.Printf(
        "stack uprobe config points:%d lib_path:%s real_file:%s non_elf_offset:0x%x first:%s last:%s",
        len(points), first.LibPath, first.RealFilePath, first.NonElfOffset, first.Name, last.Name,
    )
    this.logStackProbe("bootstrap stack uprobe", 0, first, this.buildStackProbe(first, stackUprobeUID))
}

func (this *MStack) logStackProbe(prefix string, idx int, point *config.UprobeArgs, probe *manager.Probe) {
    this.logger.Printf(
        "%s idx:%d uid:%s name:%s symbol:%s offset:0x%x non_elf_offset:0x%x attach_file:%s binary:%s attach_func:%s uaddr:0x%x uprobe_offset:0x%x",
        prefix, idx, probe.UID, point.Name, point.Symbol, point.Offset, point.NonElfOffset,
        probe.RealFilePath, probe.BinaryPath, probe.AttachToFuncName, probe.UAddress, probe.UprobeOffset,
    )
}

func (this *MStack) addStackCloneHooks() error {
    attached := 0
    failed := 0
    var firstErr error
    total := len(this.mconf.StackUprobeConf.Points)
    for i, uprobe_point := range this.mconf.StackUprobeConf.Points {
        if i == 0 {
            continue
        }
        uid := fmt.Sprintf("%s_%d", stackUprobeUID, i)
        stack_probe := this.buildStackProbe(uprobe_point, uid)
        if err := this.bpfManager.AddHook(stackUprobeUID, stack_probe); err != nil {
            failed++
            if firstErr == nil {
                firstErr = err
            }
            this.logger.Printf("skip stack uprobe idx:%d %s attach failed: %v", i, uprobe_point.String(), err)
            continue
        }
        attached++
        if this.shouldLogStackPoint(i, total) {
            this.logStackProbe("attached stack uprobe", i, uprobe_point, stack_probe)
        }
    }
    if failed > 0 {
        this.logger.Printf("stack uprobe clone hooks attached:%d failed:%d first_error:%v", attached, failed, firstErr)
    } else {
        this.logger.Printf("stack uprobe clone hooks attached:%d failed:%d", attached, failed)
    }
    if attached == 0 && failed > 0 {
        return fmt.Errorf("couldn't clone any stack uprobes, first error: %v", firstErr)
    }
    return nil
}

func (this *MStack) setupManagerOptions() {
    // 对于没有开启 CONFIG_DEBUG_INFO_BTF 的加载额外的 btf.Spec
    if this.mconf.ExternalBTF != "" {
        byteBuf, err := assets.Asset("user/assets/" + this.mconf.ExternalBTF)
        if err != nil {
            this.logger.Fatalf("[setupManagerOptions] failed, err:%v", err)
            return
        }
        spec, err := btf.LoadSpecFromReader((bytes.NewReader(byteBuf)))

        this.bpfManagerOptions = manager.Options{
            DefaultKProbeMaxActive: 512,
            VerifierOptions: ebpf.CollectionOptions{
                Programs: ebpf.ProgramOptions{
                    LogSize:     2097152,
                    KernelTypes: spec,
                },
            },
            RLimit: &unix.Rlimit{
                Cur: math.MaxUint64,
                Max: math.MaxUint64,
            },
        }
    } else {
        this.bpfManagerOptions = manager.Options{
            DefaultKProbeMaxActive: 512,
            VerifierOptions: ebpf.CollectionOptions{
                Programs: ebpf.ProgramOptions{
                    LogSize: 2097152,
                },
            },
            RLimit: &unix.Rlimit{
                Cur: math.MaxUint64,
                Max: math.MaxUint64,
            },
        }
    }
}

func (this *MStack) Start() error {
    return this.start()
}

func (this *MStack) Clone() IModule {
    mod := new(MStack)
    mod.name = this.name
    mod.mType = this.mType
    return mod
}

func (this *MStack) start() error {
    // 初始化uprobe相关设置
    err := this.setupManager()
    if err != nil {
        return err
    }
    this.setupManagerOptions()

    // 从assets中获取eBPF程序的二进制数据
    var bpfFileName = filepath.Join("user/assets", this.hookBpfFile)
    byteBuf, err := assets.Asset(bpfFileName)

    if err != nil {
        return fmt.Errorf("%s\tcouldn't find asset %v .", this.Name(), err)
    }

    // 初始化 bpfManager 循环次数越多这一步耗时越长
    if err = this.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), this.bpfManagerOptions); err != nil {
        return fmt.Errorf("couldn't init manager %v", err)
    }

    // 通过更新 BPF_MAP_TYPE_HASH 类型的 map 实现过滤设定的同步
    err = this.updateFilter()
    if err != nil {
        return err
    }

    // 启动 bpfManager
    if err = this.bpfManager.Start(); err != nil {
        return fmt.Errorf("couldn't start bootstrap manager %v .", err)
    }

    // Start() silently swallows probe attachment errors; check bootstrap probe explicitly.
    if bootstrapProbe, found := this.bpfManager.GetProbe(manager.ProbeIdentificationPair{UID: stackUprobeUID, EbpfFuncName: "probe_stack"}); found {
        if bootstrapProbe.IsRunning() {
            this.logger.Printf("bootstrap uprobe attached and running")
        } else {
            this.logger.Printf("WARNING: bootstrap uprobe NOT running (last error: %v)", bootstrapProbe.GetLastError())
        }
    } else {
        this.logger.Printf("WARNING: bootstrap uprobe probe not found in manager after Start()")
    }

    if err = this.addStackCloneHooks(); err != nil {
        return err
    }

    // 加载map信息，设置eventFuncMaps，给不同的事件指定处理事件数据的函数
    err = this.initDecodeFun()
    if err != nil {
        return err
    }

    this.startStackStatsLogger()

    return nil
}

func (this *MStack) update_map(map_name string, filter_key uint32, filter_value interface{}) {
    bpf_map, err := this.FindMap(map_name)
    if err != nil {
        panic(fmt.Sprintf("find [%s] failed, err:%v", map_name, err))
    }
    err = bpf_map.Update(unsafe.Pointer(&filter_key), filter_value, ebpf.UpdateAny)
    if err != nil {
        panic(fmt.Sprintf("update [%s] failed, err:%v", map_name, err))
    }
    if this.mconf.Debug {
        this.logger.Printf("update %s success", map_name)
    }
}

func (this *MStack) update_base_config() {
    // 更新 base_config 用作基础的过滤 比如排除 stackplz 自身相关的调用
    var filter_key uint32 = 0
    map_name := "base_config"
    filter_value := this.mconf.GetConfigMap()
    this.update_map(map_name, filter_key, unsafe.Pointer(&filter_value))
}

func (this *MStack) update_common_list(items []uint32, offset uint32) {
    map_name := "common_list"
    bpf_map, err := this.FindMap(map_name)
    if err != nil {
        panic(fmt.Sprintf("find [%s] failed, err:%v", map_name, err))
    }
    for _, v := range items {
        v += offset
        err := bpf_map.Update(unsafe.Pointer(&v), unsafe.Pointer(&v), ebpf.UpdateAny)
        if err != nil {
            panic(fmt.Sprintf("update [%s] failed, err:%v", map_name, err))
        }
    }
    if this.mconf.Debug {
        p, ok := util.START_OFFSETS[offset]
        if !ok {
            panic(fmt.Sprintf("offset%d invalid", offset))
        }
        this.logger.Printf("update %s success, count:%d offset:%s", map_name, len(items), p)
    }
}

func (this *MStack) list2string(items []uint32) string {
    var results []string
    for _, v := range items {
        results = append(results, fmt.Sprintf("%d", v))
    }
    return strings.Join(results, ",")
}

func (this *MStack) update_common_filter() {
    this.update_common_list(this.mconf.UidWhitelist, util.UID_WHITELIST_START)
    this.update_common_list(this.mconf.UidBlacklist, util.UID_BLACKLIST_START)
    this.update_common_list(this.mconf.PidWhitelist, util.PID_WHITELIST_START)
    this.update_common_list(this.mconf.PidBlacklist, util.PID_BLACKLIST_START)
    this.update_common_list(this.mconf.TidWhitelist, util.TID_WHITELIST_START)
    this.update_common_list(this.mconf.TidBlacklist, util.TID_BLACKLIST_START)
    this.logger.Printf("uid => whitelist:[%s];blacklist:[%s]", this.list2string(this.mconf.UidWhitelist), this.list2string(this.mconf.UidBlacklist))
    this.logger.Printf("pid => whitelist:[%s];blacklist:[%s]", this.list2string(this.mconf.PidWhitelist), this.list2string(this.mconf.PidBlacklist))
    this.logger.Printf("tid => whitelist:[%s];blacklist:[%s]", this.list2string(this.mconf.TidWhitelist), this.list2string(this.mconf.TidBlacklist))
    var filter_key uint32 = 0
    map_name := "common_filter"
    filter_value := this.mconf.GetCommonFilter()
    this.update_map(map_name, filter_key, unsafe.Pointer(&filter_value))
}

func (this *MStack) update_child_parent() {
    // 这个可以合并到 common_list 后面改进
    map_name := "child_parent_map"
    for _, v := range this.mconf.PidWhitelist {
        this.update_map(map_name, v, unsafe.Pointer(&v))
    }
}

func (this *MStack) update_thread_filter() {
    map_name := "thread_filter"
    bpf_map, err := this.FindMap(map_name)
    if err != nil {
        panic(fmt.Sprintf("find [%s] failed, err:%v", map_name, err))
    }

    for _, v := range this.mconf.DefaultThreadBlacklist() {
        if len(v) > 16 {
            panic(fmt.Sprintf("[%s] thread name max len is 16", v))
        }
        filter_value := THREAD_NAME_BLACKLIST
        filter_key := config.ThreadFilter{}
        copy(filter_key.ThreadName[:], v)
        err = bpf_map.Update(unsafe.Pointer(&filter_key), unsafe.Pointer(&filter_value), ebpf.UpdateAny)
        if err != nil {
            panic(fmt.Sprintf("update [%s] failed, err:%v", map_name, err))
        }
    }
    for _, v := range this.mconf.TNameBlacklist {
        if len(v) > 16 {
            panic(fmt.Sprintf("[%s] thread name max len is 16", v))
        }
        filter_value := THREAD_NAME_BLACKLIST
        filter_key := config.ThreadFilter{}
        copy(filter_key.ThreadName[:], v)
        err = bpf_map.Update(unsafe.Pointer(&filter_key), unsafe.Pointer(&filter_value), ebpf.UpdateAny)
        if err != nil {
            panic(fmt.Sprintf("update [%s] failed, err:%v", map_name, err))
        }
    }
    for _, v := range this.mconf.TNameWhitelist {
        if len(v) > 16 {
            panic(fmt.Sprintf("[%s] thread name max len is 16", v))
        }
        filter_value := THREAD_NAME_WHITELIST
        filter_key := config.ThreadFilter{}
        copy(filter_key.ThreadName[:], v)
        err = bpf_map.Update(unsafe.Pointer(&filter_key), unsafe.Pointer(&filter_value), ebpf.UpdateAny)
        if err != nil {
            panic(fmt.Sprintf("update [%s] failed, err:%v", map_name, err))
        }
    }

    if this.mconf.Debug {
        this.logger.Printf("update %s success", map_name)
    }
}

func (this *MStack) update_arg_filter() {
    map_name := "arg_filter"
    bpf_map, err := this.FindMap(map_name)
    if err != nil {
        panic(fmt.Sprintf("find [%s] failed, err:%v", map_name, err))
    }
    // w/white b/black
    // 对于返回值以特定字符串开头的进行过滤 如果要对非首个字符串参数做过滤 那么通过 | 标识占位
    // ./stackplz -n com.termux -s "openat:f0.f2,readlinkat:|f1" -f w:/data -f w:/apex -f w:/dev

    for _, filter := range config.GetFilters() {
        filter_key := uint64(filter.Filter_index)
        filter_value := filter.ToEbpfValue()
        err = bpf_map.Update(unsafe.Pointer(&filter_key), unsafe.Pointer(&filter_value), ebpf.UpdateAny)
        if err != nil {
            panic(fmt.Sprintf("update [%s] failed, err:%v", map_name, err))
        }
    }
    if this.mconf.Debug {
        this.logger.Printf("update %s success", map_name)
    }
}

func (this *MStack) update_op_list() {
    map_name := "op_list"
    bpf_map, err := this.FindMap(map_name)
    if err != nil {
        panic(fmt.Sprintf("find [%s] failed, err:%v", map_name, err))
    }
    for op_key, op_config := range argtype.GetALLOpList() {
        err := bpf_map.Update(unsafe.Pointer(&op_key), unsafe.Pointer(&op_config), ebpf.UpdateAny)
        if err != nil {
            panic(fmt.Sprintf("update [%s] failed, err:%v", map_name, err))
        }
    }

    if this.mconf.Debug {
        this.logger.Printf("update %s success", map_name)
    }
}

func (this *MStack) update_stack_config() {
    if !this.mconf.StackUprobeConf.IsEnable() {
        return
    }
    map_name := "uprobe_point_args"
    bpf_map, err := this.FindMap(map_name)
    if err != nil {
        panic(fmt.Sprintf("find [%s] failed, err:%v", map_name, err))
    }
    for _, uprobe_point := range this.mconf.StackUprobeConf.Points {
        var filter_key uint32 = uprobe_point.Index
        filter_value := uprobe_point.GetConfig()
        err := bpf_map.Update(unsafe.Pointer(&filter_key), unsafe.Pointer(&filter_value), ebpf.UpdateAny)
        if err != nil {
            panic(fmt.Sprintf("update [%s] failed, filter_key:%d, err:%v", map_name, filter_key, err))
        }
    }
    if this.mconf.Debug {
        this.logger.Printf("update %s success", map_name)
    }
}

func (this *MStack) updateFilter() (err error) {
    this.update_base_config()
    this.update_common_filter()
    this.update_child_parent()
    this.update_thread_filter()
    this.update_stack_config()
    this.update_arg_filter()
    this.update_op_list()
    return nil
}

func (this *MStack) initDecodeFun() error {
    EventsMap, err := this.FindMap("events")
    if err != nil {
        return err
    }
    this.eventMaps = append(this.eventMaps, EventsMap)
    // 根据设置添加 map 不然即使不使用的map也会创建缓冲区
    uprobestackEvent := &event.UprobeEvent{}
    this.eventFuncMaps[EventsMap] = uprobestackEvent
    return nil
}

func (this *MStack) readStackStats(stackStatsMap *ebpf.Map) ([8]uint64, error) {
    var stats [8]uint64
    for i := range stats {
        key := uint32(i)
        if err := stackStatsMap.Lookup(key, &stats[i]); err != nil {
            return stats, err
        }
    }
    return stats, nil
}

func (this *MStack) startStackStatsLogger() {
    stackStatsMap, err := this.FindMap("stack_stats")
    if err != nil {
        this.logger.Printf("stack stats unavailable: %v", err)
        return
    }

    logStats := func(stats [8]uint64) {
        this.logger.Printf(
            "stack stats entered:%d no_event:%d init_fail:%d filter_drop:%d filter_pass:%d header_saved:%d submit_ok:%d submit_err:%d",
            stats[0], stats[1], stats[2], stats[3], stats[4], stats[5], stats[6], stats[7],
        )
    }

    stats, err := this.readStackStats(stackStatsMap)
    if err != nil {
        this.logger.Printf("read stack stats failed: %v", err)
        return
    }
    logStats(stats)
    this.logTargetMapDiagnostics()
    this.logKernelUprobeDiagnostics()

    go func() {
        ticker := time.NewTicker(5 * time.Second)
        defer ticker.Stop()
        lastStats := stats
        ticks := 0
        for {
            select {
            case <-this.ctx.Done():
                stats, err := this.readStackStats(stackStatsMap)
                if err == nil && stats != lastStats {
                    logStats(stats)
                }
                return
            case <-ticker.C:
                stats, err := this.readStackStats(stackStatsMap)
                if err != nil {
                    this.logger.Printf("read stack stats failed: %v", err)
                    return
                }
                if stats != lastStats {
                    logStats(stats)
                    lastStats = stats
                }
                ticks++
                if stats[0] == 0 && ticks%3 == 0 {
                    this.logTargetMapDiagnostics()
                    this.logKernelUprobeDiagnostics()
                }
            }
        }
    }()
}

func (this *MStack) logTargetMapDiagnostics() {
    points := this.mconf.StackUprobeConf.Points
    if len(points) == 0 {
        return
    }
    pids := this.mconf.PidWhitelist
    if len(pids) == 0 {
        this.logger.Printf("stack maps diag skipped: no pid whitelist; uid whitelist cannot be mapped directly")
        return
    }

    first := points[0]
    names := []string{}
    names = appendDiagName(names, first.RealFilePath)
    names = appendDiagName(names, first.LibPath)
    for _, pid := range pids {
        this.logTargetPidMaps(pid, names, points)
    }
}

func appendDiagName(names []string, name string) []string {
    if name == "" {
        return names
    }
    names = append(names, name)
    base := filepath.Base(name)
    if base != "" && base != "." && base != "/" && base != name {
        names = append(names, base)
    }
    return names
}

func (this *MStack) logTargetPidMaps(pid uint32, names []string, points []*config.UprobeArgs) {
    content, err := util.ReadMapsByPid(pid)
    if err != nil {
        this.logger.Printf("stack maps diag pid:%d read maps failed: %v", pid, err)
        return
    }

    matched := 0
    execMatched := 0
    predicted := 0
    for _, line := range strings.Split(content, "\n") {
        if line == "" || !this.mapLineMatches(line, names) {
            continue
        }
        matched++
        this.logger.Printf("stack maps diag pid:%d map:%s", pid, line)

        start, end, perms, off, path, ok := this.parseMapLine(line)
        if !ok || !strings.Contains(perms, "x") {
            continue
        }
        execMatched++
        for i, point := range points {
            if !this.shouldLogStackPoint(i, len(points)) {
                continue
            }
            fileOff := point.Offset
            if point.NonElfOffset > 0 {
                fileOff += point.NonElfOffset
            }
            mapSize := end - start
            if fileOff >= off && fileOff < off+mapSize {
                runtimeAddr := start + (fileOff - off)
                predicted++
                this.logger.Printf(
                    "stack maps diag pid:%d idx:%d point:%s file_off:0x%x runtime:0x%x map_off:0x%x map_path:%s",
                    pid, i, point.Name, fileOff, runtimeAddr, off, path,
                )
            }
        }
    }
    this.logger.Printf("stack maps diag pid:%d matched_maps:%d executable_maps:%d predicted_logged_points:%d", pid, matched, execMatched, predicted)
}

func (this *MStack) mapLineMatches(line string, names []string) bool {
    for _, name := range names {
        if name != "" && strings.Contains(line, name) {
            return true
        }
    }
    return false
}

func (this *MStack) parseMapLine(line string) (uint64, uint64, string, uint64, string, bool) {
    var start uint64
    var end uint64
    var off uint64
    var inode uint64
    var perms string
    var dev string
    var path string
    n, err := fmt.Sscanf(line, "%x-%x %s %x %s %d %s", &start, &end, &perms, &off, &dev, &inode, &path)
    if err != nil || n < 6 {
        return 0, 0, "", 0, "", false
    }
    return start, end, perms, off, path, true
}

func (this *MStack) logKernelUprobeDiagnostics() {
    points := this.mconf.StackUprobeConf.Points
    if len(points) == 0 {
        return
    }

    paths := []string{
        "/sys/kernel/tracing/uprobe_events",
        "/sys/kernel/debug/tracing/uprobe_events",
    }
    first := points[0]
    names := []string{"probe_stack"}
    names = appendDiagName(names, first.RealFilePath)
    names = appendDiagName(names, first.LibPath)
    for _, path := range paths {
        content, err := ioutil.ReadFile(path)
        if err != nil {
            continue
        }
        matched := 0
        for _, line := range strings.Split(string(content), "\n") {
            if !this.mapLineMatches(line, names) {
                continue
            }
            if matched < 20 {
                this.logger.Printf("kernel uprobe diag %s: %s", path, line)
            }
            matched++
        }
        this.logger.Printf("kernel uprobe diag %s matched_entries:%d", path, matched)
        this.logKernelUprobeProfile(names)
        return
    }
    this.logger.Printf("kernel uprobe diag skipped: uprobe_events not readable")
    this.logKernelUprobeProfile(names)
}

func (this *MStack) logKernelUprobeProfile(names []string) {
    paths := []string{
        "/sys/kernel/tracing/uprobe_profile",
        "/sys/kernel/debug/tracing/uprobe_profile",
    }
    for _, path := range paths {
        content, err := ioutil.ReadFile(path)
        if err != nil {
            continue
        }
        matched := 0
        for _, line := range strings.Split(string(content), "\n") {
            if !this.mapLineMatches(line, names) {
                continue
            }
            if matched < 20 {
                this.logger.Printf("kernel uprobe profile %s: %s", path, line)
            }
            matched++
        }
        this.logger.Printf("kernel uprobe profile %s matched_entries:%d", path, matched)
        return
    }
    this.logger.Printf("kernel uprobe profile skipped: uprobe_profile not readable")
}

func (this *MStack) FindMap(map_name string) (*ebpf.Map, error) {
    em, found, err := this.bpfManager.GetMap(map_name)
    if err != nil {
        return em, err
    }
    if !found {
        return em, errors.New(fmt.Sprintf("cannot find map:%s", map_name))
    }
    return em, err
}

func (this *MStack) Events() []*ebpf.Map {
    return this.eventMaps
}

func (this *MStack) DecodeFun(em *ebpf.Map) (event.IEventStruct, bool) {
    fun, found := this.eventFuncMaps[em]
    return fun, found
}

func init() {
    mod := &MStack{}
    mod.name = MODULE_NAME_STACK
    mod.mType = PROBE_TYPE_UPROBE
    Register(mod)
}
