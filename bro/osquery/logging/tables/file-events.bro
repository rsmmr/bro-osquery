#! Logs processes activity.

module osquery::files;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;
		target_path: string &log;
		category: string &log;
		action: string &log;
		transaction_id: int &log;
		inode: int &log;
		uid: int &log;
		gid: int &log;
		mode: string &log;
		size: int &log;
		atime: int &log;
		mtime: int &log;
		ctime: int &log;
		md5: string &log;
		sha1: string &log;
		sha256: string &log;
		hashed: int &log;
		time_: int &log;
		eid: string &log;
		};
}

event host_file(resultInfo: osquery::ResultInfo,
		target_path: string,
		category: string,
		action: string,
		transaction_id: int,
		inode: int,
		uid: int,
		gid: int,
		mode: string,
		size: int,
		atime: int,
		mtime: int,
		ctime: int,
		md5: string,
		sha1: string,
		sha256: string,
		hashed: int,
		time_: int,
		eid: string) 
	{
	if ( resultInfo$utype != osquery::ADD )
		return;
	
	local info: Info = [$t=network_time(),
			    $host=resultInfo$host,
			    $target_path=target_path,
			    $category=category,
			    $action=action,
			    $transaction_id=transaction_id,
			    $inode=inode,
			    $uid=uid,
			    $gid=gid,
			    $mode=mode,
			    $size=size,
			    $atime=atime,
			    $mtime=mtime,
			    $ctime=ctime,
			    $md5=md5,
			    $sha1=sha1,
			    $sha256=sha256,
			    $hashed=hashed,
			    $time_=time_,
			    $eid=eid
			   ];
	
	Log::write(LOG, info);
	}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osq-file"]);
	
	local query = [$ev=host_file, $query="SELECT target_path,category,action,transaction_id,inode,uid,gid,mode,size,atime,mtime,ctime,md5,sha1,sha256,hashed,time,eid FROM file_events"];
	osquery::subscribe(query);
	}
