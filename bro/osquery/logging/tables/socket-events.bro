#! Logs processes activity.

module osquery::socket;

export {
        redef enum Log::ID += { LOG };

        type Info: record {
                t: time &log;
                host: string &log;
                action: string &log;
		pid: int &log;
		path: string &log;
		fd: string &log;
		auid: int &log;
		success: int &log;
		family: int &log;
		protocol: int &log;
		local_address: string &log;
		remote_address: string &log;
		local_port: int &log;
		remote_port: int &log;
		socket: string &log;
		time_: int &log;
		uptime: int &log;
        };
}

event host_socket(resultInfo: osquery::ResultInfo,
		  action: string,
		  pid: int,
		  path: string,
		  fd: string,
		  auid: int,
		  success: int,
		  family: int,
		  protocol: int,
		  local_address: string,
		  remote_address: string,
		  local_port: int,
		  remote_port: int,
		  socket: string,
		  time_: int,
		  uptime: int) 
	{
        if ( resultInfo$utype != osquery::ADD )
                return;

        local info: Info = [
		$t=network_time(),
		$host=resultInfo$host,
		$action=action,
		$pid=pid,
		$path=path,
		$fd=fd,
		$auid=auid,
		$success=success,
		$family=family,
		$protocol=protocol,
		$local_address=local_address,
		$remote_address=remote_address,
		$local_port=local_port,
		$remote_port=remote_port,
		$socket=socket,
		$time_=time_,
		$uptime=uptime
        ];

        Log::write(LOG, info);
        }

event bro_init()
        {
        Log::create_stream(LOG, [$columns=Info, $path="osq-socket"]);

        local query = [$ev=host_socket,$query="SELECT action,pid,path,fd,auid,success,family,protocol,local_address,remote_address,local_port,remote_port,socket,time,uptime FROM socket_events"];
        osquery::subscribe(query);
        }
