#! Logs processes activity.

module osquery::processes;

export {
        redef enum Log::ID += { LOG };

        type Info: record {
                t: time &log;
                host: string &log;
                pid: int &log;
		path: string &log;
		cmdline: string &log;
		cwd: string &log;
		uid: int &log;
		euid: int &log;
		gid: int &log;
		egid: int &log;
		start_time: int &log;
		parent: int &log;
        };
}

event host_processes(resultInfo: osquery::ResultInfo,
		pid: int, path: string, cmdline: string, cwd: string, uid: int, euid: int,
		     gid: int, egid: int, time_: int, parent: int)
        {
        if ( resultInfo$utype != osquery::ADD )
                # Just want to log new process existance.
                return;

        local info: Info = [
		$t=network_time(),
		$host=resultInfo$host,
               	$pid = pid,
                $path = path,
                $cmdline = cmdline,
                $cwd = cwd,
                $uid = uid,
                $euid = euid,
                $gid = gid,
                $egid = egid,
                $start_time = time_,
                $parent = parent
        ];

        Log::write(LOG, info);
        }

event bro_init()
        {
        Log::create_stream(LOG, [$columns=Info, $path="osq-processes"]);

        local query = [$ev=host_processes,$query="SELECT pid,path,cmdline,cwd,uid,euid,gid,egid,time,parent FROM process_events"];
        osquery::subscribe(query);
        }
