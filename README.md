# BadlyWrittenKernelDriver

includes custom virtualmemory r+w functs,
uses .dataptr comms, scans current usermode (always keep it named usermode otherwise it will not work.)

kdmapper in driver release WILL work for eac, it changes up kdmapper callback, and uses mdl allocation
