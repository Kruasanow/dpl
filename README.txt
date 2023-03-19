## DEADLINE 01.04.2023
[*]osh.py: bad get dname!
[*]osh.py: full way - dump_input/
[*]osh.py: get_file - exceptions worked...
 * Serving Flask app 'main'
 * Debug mode: off
/
/
[*]main.py: filename - eee.pcapng
[*]dns_db_addiction.py: dump name - eee.pcapng
[*]osh.py element choosed - eee.pcapng
[*]osh.py: full way - dump_input/eee.pcapng
[*]osh.py: cap for pyshark - <FileCapture dump_input/eee.pcapng>
<FileCapture dump_input/eee.pcapng>
[*]main.py: osh.cap after choose - <FileCapture dump_input/eee.pcapng>
[*]main.py: file - <FileStorage: 'eee.pcapng' ('application/x-pcapng')>
[*]dns_prepare_fdb.py: arr - []
[]
[*]dns_db_addiction.py: bad array - []
[*]dns_prepare_fdb.py: arr - <FileCapture dump_input/eee.pcapng>
<FileCapture dump_input/eee.pcapng>
[2023-03-15 19:15:02,585] ERROR in app: Exception on / [POST]
Traceback (most recent call last):
  File "/usr/local/lib/python3.8/dist-packages/flask/app.py", line 2528, in wsgi_app
    response = self.full_dispatch_request()
  File "/usr/local/lib/python3.8/dist-packages/flask/app.py", line 1825, in full_dispatch_request
    rv = self.handle_user_exception(e)
  File "/usr/local/lib/python3.8/dist-packages/flask/app.py", line 1823, in full_dispatch_request
    rv = self.dispatch_request()
  File "/usr/local/lib/python3.8/dist-packages/flask/app.py", line 1799, in dispatch_request
    return self.ensure_sync(self.view_functions[rule.endpoint])(**view_args)
  File "main.py", line 52, in index
    get_dns_profile(c) # TUT VSE IDET PO PIZDE
  File "/home/ubuntu18/Desktop/new/dpl/dns_prepare_fdb.py", line 149, in get_dns_profile
    array = to_dns_arr(arr)
  File "/home/ubuntu18/Desktop/new/dpl/dns_prepare_fdb.py", line 23, in to_dns_arr
    for pac in a:
  File "/usr/local/lib/python3.8/dist-packages/pyshark/capture/capture.py", line 212, in _packets_from_tshark_sync
    tshark_process = existing_process or self.eventloop.run_until_complete(
  File "/usr/lib/python3.8/asyncio/base_events.py", line 616, in run_until_complete
    return future.result()
  File "/usr/local/lib/python3.8/dist-packages/pyshark/capture/capture.py", line 346, in _get_tshark_process
    tshark_process = await asyncio.create_subprocess_exec(*parameters,
  File "/usr/lib/python3.8/asyncio/subprocess.py", line 236, in create_subprocess_exec
    transport, protocol = await loop.subprocess_exec(
  File "/usr/lib/python3.8/asyncio/base_events.py", line 1630, in subprocess_exec
    transport = await self._make_subprocess_transport(
  File "/usr/lib/python3.8/asyncio/unix_events.py", line 194, in _make_subprocess_transport
    raise RuntimeError("asyncio.get_child_watcher() is not activated, "
RuntimeError: asyncio.get_child_watcher() is not activated, subprocess support is not installed.

