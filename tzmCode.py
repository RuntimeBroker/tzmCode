import ida_funcs
import ida_idaapi
import idautils
import idc

banner = \
    '''
    IDA特征码提取插件
    1.火哥的特征码提取插件升级成py3
    2.特征码提取优化版本
    3.提取特征码快捷键是:Ctrl-Alt-x
    '''


class MyPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL | ida_idaapi.PLUGIN_MULTI
    comment = "IDA特征码提取插件"
    help = "提取特征码快捷键是:Ctrl-Alt-x"
    wanted_name = "IDA特征码提取插件"
    wanted_hotkey = "Ctrl-Alt-x"

    def init(self):
        self.gen_banner()
        return MyPlugmod()

    def gen_banner(self):
        print(15 * "===")
        print(banner);
        print(15 * "===")


# 这个地方写你插件的主要逻辑
class MyPlugmod(ida_idaapi.plugmod_t):
    def __del__(self):
        pass

    def run(self, arg):
        print(">>>插件已经运行<<<")
        # 拿到鼠标选中的起始地址和结束地址，计算出这一块区域的大小
        startAddr = idc.read_selection_start();
        endAddr = idc.read_selection_end();
        size = endAddr - startAddr;
        ea = startAddr;

        result = "";

        for i in range(size):
            op1 = idc.get_operand_type(ea, 0);
            op2 = idc.get_operand_type(ea, 1);
            #当前指令的大小
            instruction_size = idc.get_item_size(ea);
            #print(f"instruction_size:{instruction_size}");
            # 情况 1：操作数是寄存器
            if op1 == idc.o_reg and (op2 == idc.o_reg or op2 == idc.o_void or op2 == idc.o_phrase):
                for byte in range(0, instruction_size):
                    result += self.formatByte(ea + byte);
            # 情况 2：操作数是内存地址偏移或立即数
            # elif (op1 == idc.o_reg and op2 == idc.o_imm) or (op1 == idc.o_reg and op2 == idc.o_displ) or (op1 == idc.o_displ and and op2 == idc.o_reg) or (op1 == idc.o_displ and op2 == idc.o_imm):
            elif (op1 == idc.o_reg and op2 == idc.o_displ) or (op1 == idc.o_displ and op2 == idc.o_reg) or (
                    op1 == idc.o_displ and op2 == idc.o_imm):
                result += self.formatByte(ea) + self.formatByte(ea + 1);
                for byte in range(2, instruction_size):
                    result += "*";
                    # result += self.formatByte(ea+ byte);
            # 情况 3：短指针（o_phrase）和寄存器
            elif op1 == idc.o_phrase and op2 == idc.o_reg:
                for byte in range(0, instruction_size):
                    result += self.formatByte(ea + byte)
            else:
                result += self.calcStr(ea, instruction_size);
            #每次更新完一条指令后，将当前地址往下走一个指令的大小
            ea = ea + instruction_size
            if ea >= (startAddr + size):
                break
        print(f"start_addr:{hex(startAddr)}")
        print(f"end_addr:{hex(endAddr)}")
        print("{}  Offset:{}".format(idc.get_func_name(startAddr), hex(startAddr - idc.get_func_attr(startAddr, 0))))
        print(">>>特征码提取完成<<<")
        print(result)

    def calcStr(self, ea, endcount):
        hstr = ""
        firstByte = self.formatByte(ea)
        hstr += self.formatByte(ea)
        hstr = hstr + self.formatByte(ea + 1) if (firstByte == "FF" or firstByte == "66" or firstByte == "67") else hstr
        hstr = hstr + int((endcount - len(hstr) / 2)) * "*" if endcount >= 2 else hstr
        return hstr

    def formatByte(self, ea):
        return "{:02X}".format(idc.get_wide_byte(ea));


def PLUGIN_ENTRY():
    return MyPlugin();
