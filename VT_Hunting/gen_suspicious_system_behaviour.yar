import "vt"

rule suspicious_system_behaviour {
  meta:
    author = "dominicchua@"
    description = "targeting files that that exhibits suspicious behaviours"
  condition:
    for any persistance in vt.behaviour.processes_created: (
      persistance icontains "/c schtasks /Create /SC"  // creates a scheduled task
    ) or
    for any evasion in vt.behaviour.processes_created: (
      evasion icontains "wevtutil cl" or //clears event logs (wevtutil cl security, application, system)
      evasion icontains "fsutil  usn deletejournal /D"
    ) or
    for any named_pipe in vt.behaviour.processes_created: ( //named pipes or IPC
      named_pipe startswith "\"C:\\Windows " and
      named_pipe icontains "\\\\.\\pipe\\"
    ) or 
    for any create_user in vt.behaviour.processes_created: ( //add user 
        create_user icontains "net1 user" or 
        create_user icontains "net user " or
        create_user icontains  "net localgroup administrators"
     )
}
 

