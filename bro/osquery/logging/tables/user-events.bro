#! Logs processeiosts activity.

module osquery::user;

export {
        redef enum Log::ID += { LOG };

        type Info: record {
                t: time &log;
                host: string &log;
                uid: string &log;
                auid: string &log;
                pid: int &log;
	        message: string &log;
	        type_: int &log;
		path: string &log;
		address: string &log;
		terminal: string &log;
		time_: int &log;
		uptime: int &log;
        };
}

event host_user(resultInfo: osquery::ResultInfo,
		uid: string,
		auid: string,
		pid: int,
		message: string,
		type_: int,
		path: string,
		address: string,
		terminal: string,
		time_: int,
		uptime: int)
        {
        if ( resultInfo$utype != osquery::ADD )
                # Just want to log new process existance.
                return;

        local info: Info = [
		$t=network_time(),
		$host=resultInfo$host,
               	$uid = uid,
               	$auid = auid,
               	$pid = pid,
		$message = message,
		$type_ = type_,
                $path = path,
		$address = address,
		$terminal = terminal,
	        $time_ = time_,
		$uptime = uptime
        ];

        Log::write(LOG, info);
        }

event bro_init()
        {
        Log::create_stream(LOG, [$columns=Info, $path="osq-user"]);

        local query = [$ev=host_user,$query="SELECT uid,auid,pid,message,type,path,address,terminal,time,uptime FROM user_events"];
        osquery::subscribe(query);
        }
