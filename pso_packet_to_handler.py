import re
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing.Function import FunctionUpdateType
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.util import UndefinedFunction
from ghidra.program.model.address import AddressSet
from ghidra.program.model.data import PointerDataType
from ghidra.program.model.listing import ParameterImpl

tm = ConsoleTaskMonitor()
fm = currentProgram.getFunctionManager()

login_handler_table = getDataAt(toAddr(0x009a6800))
ship_handler_table = getDataAt(toAddr(0x00a0f920))
packet0x60_handler_table = getDataAt(toAddr(0x00a0fba0))
ignore_funcs = [toAddr(0x0061cdb0), toAddr(0x00779df0)]

MSG1_TYPE = 0x0001
WELCOME_TYPE = 0x0002
BB_WELCOME_TYPE = 0x0003
SECURITY_TYPE = 0x0004
TYPE_05 = 0x0005
CHAT_TYPE = 0x0006
BLOCK_LIST_TYPE = 0x0007
GAME_LIST_TYPE = 0x0008
INFO_REQUEST_TYPE = 0x0009
DC_GAME_CREATE_TYPE = 0x000C
MENU_SELECT_TYPE = 0x0010
INFO_REPLY_TYPE = 0x0011
QUEST_CHUNK_TYPE = 0x0013
LOGIN_WELCOME_TYPE = 0x0017
REDIRECT_TYPE = 0x0019
MSG_BOX_TYPE = 0x001A
PING_TYPE = 0x001D
LOBBY_INFO_TYPE = 0x001F
GUILD_SEARCH_TYPE = 0x0040
GUILD_REPLY_TYPE = 0x0041
QUEST_FILE_TYPE = 0x0044
GAME_COMMAND0_TYPE = 0x0060
CHAR_DATA_TYPE = 0x0061
GAME_COMMAND2_TYPE = 0x0062
GAME_JOIN_TYPE = 0x0064
GAME_ADD_PLAYER_TYPE = 0x0065
GAME_LEAVE_TYPE = 0x0066
LOBBY_JOIN_TYPE = 0x0067
LOBBY_ADD_PLAYER_TYPE = 0x0068
LOBBY_LEAVE_TYPE = 0x0069
GAME_COMMANDC_TYPE = 0x006C
GAME_COMMANDD_TYPE = 0x006D
DONE_BURSTING_TYPE = 0x006F
SIMPLE_MAIL_TYPE = 0x0081
LOBBY_LIST_TYPE = 0x0083
LOBBY_CHANGE_TYPE = 0x0084
LOBBY_ARROW_LIST_TYPE = 0x0088
LOGIN_88_TYPE = 0x0088
LOBBY_ARROW_CHANGE_TYPE = 0x0089
LOBBY_NAME_TYPE = 0x008A
LOGIN_8A_TYPE = 0x008A
LOGIN_8B_TYPE = 0x008B
DCNTE_CHAR_DATA_REQ_TYPE = 0x008D
DCNTE_SHIP_LIST_TYPE = 0x008E
DCNTE_BLOCK_LIST_REQ_TYPE = 0x008F
LOGIN_90_TYPE = 0x0090
LOGIN_92_TYPE = 0x0092
LOGIN_93_TYPE = 0x0093
CHAR_DATA_REQUEST_TYPE = 0x0095
CHECKSUM_TYPE = 0x0096
CHECKSUM_REPLY_TYPE = 0x0097
LEAVE_GAME_PL_DATA_TYPE = 0x0098
SHIP_LIST_REQ_TYPE = 0x0099
LOGIN_9A_TYPE = 0x009A
LOGIN_9C_TYPE = 0x009C
LOGIN_9D_TYPE = 0x009D
LOGIN_9E_TYPE = 0x009E
SHIP_LIST_TYPE = 0x00A0
BLOCK_LIST_REQ_TYPE = 0x00A1
QUEST_LIST_TYPE = 0x00A2
QUEST_INFO_TYPE = 0x00A3
DL_QUEST_LIST_TYPE = 0x00A4
DL_QUEST_FILE_TYPE = 0x00A6
DL_QUEST_CHUNK_TYPE = 0x00A7
QUEST_END_LIST_TYPE = 0x00A9
QUEST_STATS_TYPE = 0x00AA
QUEST_LOAD_DONE_TYPE = 0x00AC
TEXT_MSG_TYPE = 0x00B0
TIMESTAMP_TYPE = 0x00B1
EP3_RANK_UPDATE_TYPE = 0x00B7
EP3_CARD_UPDATE_TYPE = 0x00B8
EP3_COMMAND_TYPE = 0x00BA
CHOICE_OPTION_TYPE = 0x00C0
GAME_CREATE_TYPE = 0x00C1
CHOICE_SETTING_TYPE = 0x00C2
CHOICE_SEARCH_TYPE = 0x00C3
CHOICE_REPLY_TYPE = 0x00C4
C_RANK_TYPE = 0x00C5
BLACKLIST_TYPE = 0x00C6
AUTOREPLY_SET_TYPE = 0x00C7
AUTOREPLY_CLEAR_TYPE = 0x00C8
GAME_COMMAND_C9_TYPE = 0x00C9
EP3_SERVER_DATA_TYPE = 0x00CA
GAME_COMMAND_CB_TYPE = 0x00CB
TRADE_0_TYPE = 0x00D0
TRADE_1_TYPE = 0x00D1
TRADE_2_TYPE = 0x00D2
TRADE_3_TYPE = 0x00D3
TRADE_4_TYPE = 0x00D4
GC_MSG_BOX_TYPE = 0x00D5
GC_MSG_BOX_CLOSED_TYPE = 0x00D6
GC_GBA_FILE_REQ_TYPE = 0x00D7
INFOBOARD_TYPE = 0x00D8
INFOBOARD_WRITE_TYPE = 0x00D9
LOBBY_EVENT_TYPE = 0x00DA
GC_VERIFY_LICENSE_TYPE = 0x00DB
EP3_MENU_CHANGE_TYPE = 0x00DC
BB_GUILDCARD_HEADER_TYPE = 0x01DC
BB_GUILDCARD_CHUNK_TYPE = 0x02DC
BB_GUILDCARD_CHUNK_REQ_TYPE = 0x03DC
BB_OPTION_REQUEST_TYPE = 0x00E0
BB_OPTION_CONFIG_TYPE = 0x00E2
BB_CHARACTER_SELECT_TYPE = 0x00E3
BB_CHARACTER_ACK_TYPE = 0x00E4
BB_CHARACTER_UPDATE_TYPE = 0x00E5
BB_SECURITY_TYPE = 0x00E6
BB_FULL_CHARACTER_TYPE = 0x00E7
BB_CHECKSUM_TYPE = 0x01E8
BB_CHECKSUM_ACK_TYPE = 0x02E8
BB_GUILD_REQUEST_TYPE = 0x03E8
BB_ADD_GUILDCARD_TYPE = 0x04E8
BB_DEL_GUILDCARD_TYPE = 0x05E8
BB_SET_GUILDCARD_TEXT_TYPE = 0x06E8
BB_ADD_BLOCKED_USER_TYPE = 0x07E8
BB_DEL_BLOCKED_USER_TYPE = 0x08E8
BB_SET_GUILDCARD_COMMENT_TYPE = 0x09E8
BB_SORT_GUILDCARD_TYPE = 0x0AE8
BB_PARAM_HEADER_TYPE = 0x01EB
BB_PARAM_CHUNK_TYPE = 0x02EB
BB_PARAM_CHUNK_REQ_TYPE = 0x03EB
BB_PARAM_HEADER_REQ_TYPE = 0x04EB
EP3_GAME_CREATE_TYPE = 0x00EC
BB_SETFLAG_TYPE = 0x00EC
BB_UPDATE_OPTION_FLAGS = 0x01ED
BB_UPDATE_SYMBOL_CHAT = 0x02ED
BB_UPDATE_SHORTCUTS = 0x03ED
BB_UPDATE_KEY_CONFIG = 0x04ED
BB_UPDATE_PAD_CONFIG = 0x05ED
BB_UPDATE_TECH_MENU = 0x06ED
BB_UPDATE_CONFIG = 0x07ED
BB_SCROLL_MSG_TYPE = 0x00EE
SUBCMD_GUILDCARD = 0x06
SUBCMD_PICK_UP = 0x5A
SUBCMD_ITEMREQ = 0x60
SUBCMD_BITEMREQ = 0xA2
SUBCMD_SHOPREQ = 0xB5
SUBCMD_SHOPBUY = 0xB7
SUBCMD_OPEN_BANK = 0xBB
SUBCMD_BANK_ACTION = 0xBD
SUBCMD_SYMBOL_CHAT = 0x07
SUBCMD_HIT_MONSTER = 0x0A
SUBCMD_HIT_OBJ = 0x0B
SUBCMD_TELEPORT = 0x17
SUBCMD_SET_AREA = 0x1F
SUBCMD_SET_AREA_21 = 0x21
SUBCMD_LOAD_22 = 0x22
SUBCMD_FINISH_LOAD = 0x23
SUBCMD_SET_POS_24 = 0x24
SUBCMD_EQUIP = 0x25
SUBCMD_REMOVE_EQUIP = 0x26
SUBCMD_USE_ITEM = 0x27
SUBCMD_DELETE_ITEM = 0x29
SUBCMD_DROP_ITEM = 0x2A
SUBCMD_TAKE_ITEM = 0x2B
SUBCMD_TALK_NPC = 0x2C
SUBCMD_DONE_NPC = 0x2D
SUBCMD_LEVELUP = 0x30
SUBCMD_LOAD_3B = 0x3B
SUBCMD_SET_POS_3E = 0x3E
SUBCMD_SET_POS_3F = 0x3F
SUBCMD_MOVE_SLOW = 0x40
SUBCMD_MOVE_FAST = 0x42
SUBCMD_OBJHIT_PHYS = 0x46
SUBCMD_OBJHIT_TECH = 0x47
SUBCMD_USED_TECH = 0x48
SUBCMD_TAKE_DAMAGE1 = 0x4B
SUBCMD_TAKE_DAMAGE2 = 0x4C
SUBCMD_TALK_DESK = 0x52
SUBCMD_WARP_55 = 0x55
SUBCMD_LOBBY_ACTION = 0x58
SUBCMD_DEL_MAP_ITEM = 0x59
SUBCMD_DROP_STACK = 0x5D
SUBCMD_BUY = 0x5E
SUBCMD_ITEMDROP = 0x5F
SUBCMD_DESTROY_ITEM = 0x63
SUBCMD_CREATE_PIPE = 0x68
SUBCMD_SPAWN_NPC = 0x69
SUBCMD_BURST_DONE = 0x72
SUBCMD_WORD_SELECT = 0x74
SUBCMD_KILL_MONSTER = 0x76
SUBCMD_SYNC_REG = 0x77
SUBCMD_GOGO_BALL = 0x79
SUBCMD_CMODE_GRAVE = 0x7C
SUBCMD_WARP = 0x94
SUBCMD_CHANGE_STAT = 0x9A
SUBCMD_LOBBY_CHAIR = 0xAB
SUBCMD_CHAIR_DIR = 0xAF
SUBCMD_CHAIR_MOVE = 0xB0
SUBCMD_SHOPINV = 0xB6
SUBCMD_BANK_INV = 0xBC
SUBCMD_CREATE_ITEM = 0xBE
SUBCMD_JUKEBOX = 0xBF
SUBCMD_GIVE_EXP = 0xBF
SUBCMD_DROP_POS = 0xC3
SUBCMD_SORT_INV = 0xC4
SUBCMD_MEDIC = 0xC5
SUBCMD_REQ_EXP = 0xC8

# server->client packets
s2c_packets = [
    #[BB_WELCOME_TYPE, "bb_welcome_pkt"], # skipping because of peetles_header messing up the params and i cba
    #[BLOCK_LIST_TYPE, "bb_block_list_pkt"], # identical to ship list
    [REDIRECT_TYPE, "bb_redirect_pkt"],
    [TIMESTAMP_TYPE, "bb_timestamp_pkt"],
    [BB_SECURITY_TYPE, "bb_security_pkt"],
    [INFO_REPLY_TYPE, "bb_info_reply_pkt"],
    [BB_SCROLL_MSG_TYPE, "bb_info_reply_pkt"],
    [LOBBY_LIST_TYPE, "bb_lobby_list_pkt"],
    [LOBBY_JOIN_TYPE, "bb_lobby_join_pkt"],
    [LOBBY_LEAVE_TYPE, "bb_lobby_leave_pkt"],
    [GAME_LEAVE_TYPE, "bb_lobby_leave_pkt"],
    [CHAT_TYPE, "bb_chat_pkt"],
    [GUILD_REPLY_TYPE, "bb_guild_reply_pkt"],
    [SIMPLE_MAIL_TYPE, "bb_simple_mail_pkt"],
    [GAME_JOIN_TYPE, "bb_game_join_pkt"],
    [GAME_LIST_TYPE, "bb_game_list_pkt"],
    [QUEST_INFO_TYPE, "bb_msg_box_pkt"],
    [LOBBY_NAME_TYPE, "bb_msg_box_pkt"],
    [QUEST_LIST_TYPE, "bb_quest_list_pkt"],
    [QUEST_CHUNK_TYPE, "bb_quest_chunk_pkt"],
    [LOBBY_ARROW_LIST_TYPE, "bb_arrow_list_pkt"],
    [SHIP_LIST_TYPE, "bb_ship_list_pkt"],
    [INFOBOARD_TYPE, "bb_read_info_pkt"],
    #[BB_OPTION_CONFIG_TYPE, "bb_opt_config_pkt"], # peetles_header
    #[BB_CHARACTER_ACK_TYPE, "bb_char_ack_pkt"], # peetles_header
    [BB_CHECKSUM_ACK_TYPE, "bb_checksum_ack_pkt"],
    [BB_GUILDCARD_HEADER_TYPE, "bb_guildcard_hdr_pkt"],
    [BB_GUILDCARD_CHUNK_TYPE, "bb_guildcard_chunk_pkt"],
    [BB_PARAM_HEADER_TYPE, "bb_param_hdr_pkt"],
    [BB_PARAM_CHUNK_TYPE, "bb_param_chunk_pkt"],
    #[BB_CHARACTER_UPDATE_TYPE, "bb_char_preview_pkt"], # peetles_header
    [BB_FULL_CHARACTER_TYPE, "bb_full_char_pkt"]
]

packets_0x60 = [
    [SUBCMD_HIT_MONSTER, "packet0x60_subcmd_bb_mhit_pkt_t"],
    [SUBCMD_SET_AREA, "packet0x60_subcmd_bb_set_area_t"],
    [SUBCMD_SET_AREA_21, "packet0x60_subcmd_bb_set_area_t"],
    [SUBCMD_EQUIP, "packet0x60_subcmd_bb_equip_t"],
    [SUBCMD_REMOVE_EQUIP, "packet0x60_subcmd_bb_equip_t"],
    [SUBCMD_DROP_ITEM, "packet0x60_subcmd_bb_drop_item_t"],
    [SUBCMD_SET_POS_3E, "packet0x60_subcmd_bb_set_pos_t"],
    [SUBCMD_SET_POS_3F, "packet0x60_subcmd_bb_set_pos_t"],
    [SUBCMD_MOVE_SLOW, "packet0x60_subcmd_bb_move_t"],
    [SUBCMD_MOVE_FAST, "packet0x60_subcmd_bb_move_t"],
    [SUBCMD_DELETE_ITEM, "packet0x60_subcmd_bb_destroy_item_t"],
    [SUBCMD_WORD_SELECT, "packet0x60_subcmd_bb_word_select_t"],
    [SUBCMD_DROP_POS, "packet0x60_subcmd_bb_drop_pos_t"],
    [SUBCMD_SORT_INV, "packet0x60_subcmd_bb_sort_inv_t"],
    [SUBCMD_USED_TECH, "packet0x60_subcmd_bb_used_tech_t"],
    [SUBCMD_TAKE_DAMAGE1, "packet0x60_subcmd_bb_take_damage_t"],
    [SUBCMD_TAKE_DAMAGE2, "packet0x60_subcmd_bb_take_damage_t"],
    [SUBCMD_GUILDCARD, "packet0x60_subcmd_bb_gcsend_t"],
    [SUBCMD_PICK_UP, "packet0x60_subcmd_bb_pick_up_t"],
    [SUBCMD_SHOPINV, "packet0x60_subcmd_bb_shop_inv_t"],
    [SUBCMD_ITEMDROP, "packet0x60_subcmd_bb_itemgen_t"],
    [SUBCMD_DEL_MAP_ITEM, "packet0x60_subcmd_bb_destroy_map_item_t"],
    [SUBCMD_DROP_STACK, "packet0x60_subcmd_bb_drop_stack_t"],
    [SUBCMD_BANK_INV, "packet0x60_subcmd_bb_bank_inv_t"],
    [SUBCMD_GIVE_EXP, "packet0x60_subcmd_bb_exp_t"],
    [0x20, "packet0x60_subcmd_bb_set_pos_t"]
]

def find_handler(table, find_opcode, opcode_idx, handler_idx):
    i = 0
    while True:
        entry = table.getComponent(i)
        if not entry:
            break
        entry_opcode = entry.getComponent(opcode_idx).getValue().getUnsignedValue()
        if entry_opcode == find_opcode:
            entry_handler = entry.getComponent(handler_idx)
            return entry_handler
        i += 1
    return None

def define_function_at(addr, name):
    orig_fn = UndefinedFunction.findFunctionUsingSimpleBlockModel(currentProgram, addr, tm)
    if not orig_fn:
        raise Exception("failed to find a function at " + addr.toString())
    entry = addr
    start = addr
    end = addr
    # try find end of function, this is probably a really bad way of doing this
    while True:
        addr = addr.add(1)
        fn = UndefinedFunction.findFunctionUsingSimpleBlockModel(currentProgram, addr, tm)
        if not fn or not fn.equals(orig_fn):
            break
        end = addr
    return fm.createFunction(name, entry, AddressSet(start, end), SourceType.USER_DEFINED)

def get_or_define_function_at(func_addr, name, verbose=True):
    func = getFunctionAt(func_addr)
    if not func:
        # no function, try create one
        start()
        func = define_function_at(func_addr, name)
        end(True)
        if not func:
            raise Exception("failed to create function at " + func_addr.toString())
        if verbose:
            print("created function " + func.getName() + " at " + func_addr.toString())
    return func

def should_ignore_function(addr):
    for ignore_addr in ignore_funcs:
        if addr.equals(ignore_addr):
            return True
    return False

def rename_function_if_not_user_defined(func, new_name):
    if func.getSymbol().getSource() != SourceType.USER_DEFINED and func.getName() != new_name:
        func.setName(new_name, SourceType.USER_DEFINED)

def set_handler_packet_type(handler, opcode, packet_type, param_idx, name_prefix):
    if not handler:
        return
    # get function
    new_name = name_prefix + hex(opcode)
    param_name = "packet"
    func_addr = handler.getValue()
    if func_addr.getOffset() == 0:
        return
    if should_ignore_function(func_addr):
        return
    func = get_or_define_function_at(func_addr, new_name)
    rename_function_if_not_user_defined(func, new_name)
    # update function signature
    params = list(func.getParameters())
    if len(params) > param_idx and params[param_idx].getDataType().isEquivalent(packet_type):
        # nothing to do
        return
    if len(params) < param_idx + 1:
        if len(params) < param_idx:
            raise Exception("not enough params in function at " + func_addr.toString())
        stack_offset = 4
        for param in params:
            if param.isStackVariable():
                varnode = param.getFirstStorageVarnode()
                stack_offset = max(stack_offset, varnode.getOffset() + varnode.getSize())
        params.append(ParameterImpl(param_name, packet_type, stack_offset, currentProgram, SourceType.USER_DEFINED))
        print("added param to function at " + func_addr.toString())
    if params[param_idx].isAutoParameter():
        print("skipping autoparam at " + func_addr.toString())
        return
    params[param_idx].setDataType(packet_type, True, True, SourceType.USER_DEFINED)
    func.replaceParameters(params, FunctionUpdateType.CUSTOM_STORAGE, True, SourceType.USER_DEFINED)
    print("updated signature of function " + func.getName() + " at " + func_addr.toString())

def set_this_type(handler, new_type, opcode, name_prefix):
    if not handler:
        return
    new_name = name_prefix + hex(opcode)
    func_addr = handler.getValue()
    if func_addr.getOffset() == 0:
        return
    if should_ignore_function(func_addr):
        return
    func = get_or_define_function_at(func_addr, new_name)
    func.setCallingConvention("__thiscall")
    rename_function_if_not_user_defined(func, new_name)
    if not func.hasCustomVariableStorage():
        func.setCustomVariableStorage(True)
    params = list(func.getParameters())
    if len(params) == 0:
        print("skipping function with no params at " + func_addr.toString())
        return
    if params[0].getDataType().isEquivalent(new_type):
        return
    params[0].setDataType(new_type, True, True, SourceType.USER_DEFINED)
    func.replaceParameters(params, FunctionUpdateType.CUSTOM_STORAGE, True, SourceType.USER_DEFINED)
    print("updated 'this' type of function " + func.getName() + " at " + func_addr.toString())

def get_datatype_by_name(name):
    dts = getDataTypes(name)
    if len(dts) != 1:
        raise Exception("Could not determine datatype " + name)
    return dts[0]

# change type names to concrete types
for entry in s2c_packets + packets_0x60:
    entry[1] = PointerDataType.getPointer(get_datatype_by_name(entry[1]), 4)

# set type of "this" in ship handlers
ship_name_prefix = "handle_ship_packet"
ship_this_type = PointerDataType.getPointer(get_datatype_by_name("ship_connection_manager"), 4)
i = 0
start()
while True:
    entry = ship_handler_table.getComponent(i)
    if not entry:
        break
    opcode = int(entry.getComponent(0).getValue().getUnsignedValue())
    handler = entry.getComponent(1)
    set_this_type(handler, ship_this_type, opcode, ship_name_prefix)
    i += 1
end(True)

# find and fix handler function signatures
start()
for (opcode, packet_type) in s2c_packets:
    set_handler_packet_type(find_handler(login_handler_table, opcode, 0, 1), opcode, packet_type, 1, "handle_login_packet")
    set_handler_packet_type(find_handler(ship_handler_table, opcode, 0, 1), opcode, packet_type, 1, ship_name_prefix)

for (opcode, packet_type) in packets_0x60:
    set_handler_packet_type(find_handler(packet0x60_handler_table, opcode, 0, 4), opcode, packet_type, 0, "handle_packet0x60_subcommand")
end(True)
