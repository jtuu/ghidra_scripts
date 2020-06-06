#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


needle = 0xa5

action_table = getDataAt(toAddr(0x00a0fba0))

i = 0
while True:
    action = action_table.getComponent(i)
    if not action:
        break
    action_type = action.getComponent(0).getValue().getUnsignedValue()
    if action_type == needle:
        print(action.getComponent(4))
        break
    i += 1