from java.util.function import Function
from ghidra.formats.gfilesystem import SelectFromListDialog

class func(Function):
    def __init__(self, fn):
        self.apply = fn

def list_select_prompt(title, text, items, stringifier = None):
    if stringifier is None:
        stringifier = func(lambda x: x)
    tool = state.getTool()
    return SelectFromListDialog.selectFromList(items, title, text, stringifier)

map_enemy_table = getDataAt(toAddr(0x009fba60))

def find_enemy_constructor():
    dt = getDataTypes("enemy_skin")[0]
    enemy = int(list_select_prompt("pso_find_enemy_constructor.py", "Select enemy type", list(dt.getValues()), func(lambda val: dt.getName(val))))
    for i in range(map_enemy_table.getNumComponents()):
        lst = getDataAt(map_enemy_table.getComponentAt(i * 4).getValue())
        for j in range(lst.getNumComponents()):
            struct = lst.getComponentAt(j * 0x10)
            if int(struct.getComponentAt(0).getValue().getValue()) == enemy:
                return struct.getComponentAt(4).getValue()


print(find_enemy_constructor())
