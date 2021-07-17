#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


needle = 0xb2

handler_table = getDataAt(toAddr(0x00a0f920))

i = 0
while True:
    action = handler_table.getComponent(i)
    if not action:
        break
    action_type = action.getComponent(0).getValue().getUnsignedValue()
    if action_type == needle:
        print(action.getComponent(1))
        break
    i += 1
