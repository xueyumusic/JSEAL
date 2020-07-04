package org.homobit.jseal;

import java.io.IOException;
import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;

public class Utils {
    public static final BigDecimal readUnsignedLong(long value) throws IOException {
        if (value >= 0)
            return new BigDecimal(value);
        long lowValue = value & 0x7fffffffffffffffL;
        return BigDecimal.valueOf(lowValue).add(BigDecimal.valueOf(Long.MAX_VALUE)).add(BigDecimal.valueOf(1));
    }

    public static byte[] GetBytes(int value)
    {
        ByteBuffer buffer = ByteBuffer.allocate(4).order(ByteOrder.nativeOrder());
        buffer.putInt(value);
        return buffer.array();
    }

    public static byte[] GetBytes(long value)
    {
        ByteBuffer buffer = ByteBuffer.allocate(8).order(ByteOrder.nativeOrder());
        buffer.putLong(value);
        return buffer.array();
    }

    public static String byteToHex(byte[] bytes){
        String strHex = "";
        StringBuilder sb = new StringBuilder("");
        for (int n = 0; n < bytes.length; n++) {
            strHex = Integer.toHexString(bytes[n] & 0xFF);
            sb.append((strHex.length() == 1) ? "0" + strHex : strHex); // 每个字节由两个字符表示，位数不够，高位补0
        }
        return sb.toString().trim();
    }

    public static void printMatrix(List<Long> matrix, int row_size) {
        int print_size = 5;
        System.out.println();
        System.out.print("    [");
        for (int i = 0; i < print_size; i++) {
            System.out.print(matrix.get(i)+",");
        }
        System.out.print(" ...,");
        for (int i = row_size - print_size; i < row_size; i++) {
            System.out.print(matrix.get(i) + ((i != row_size - 1) ? "," : " ]\n"));
        }
        System.out.print("    [");
        for (int i = row_size; i < row_size + print_size; i++) {
            System.out.print(matrix.get(i) + ",");
        }
        System.out.print(" ...,");
        for (int i = 2 * row_size - print_size; i < 2 * row_size; i++) {
            System.out.print(matrix.get(i) + ((i != 2 * row_size - 1) ? "," : " ]\n"));
        }
        System.out.println();

    }
    public static void printVector(List<Double> vec) {
        printVector(vec, 4, 3);
    }
    public static void printVector(List<Double> vec, int print_size, int prec) {
        int slot_count = vec.size();
        String formatStr = "%."+prec+"f";
        System.out.println();
        if(slot_count <= 2 * print_size) {
            System.out.print("    [");
            for (int i = 0; i < slot_count; i++) {
                System.out.print(" " + String.format(formatStr, vec.get(i)) + ((i != slot_count - 1) ? "," : " ]\n"));
            }
        } else {
            //vec.resize(std::max(vec.size(), 2 * print_size));
            System.out.print("    [");
            for (int i = 0; i < print_size; i++) {
                System.out.print(" " + String.format(formatStr, vec.get(i)) + ",");
            }
            if(vec.size() > 2 * print_size) {
                System.out.print(" ...,");
            }
            for (int i = slot_count - print_size; i < slot_count; i++) {
                System.out.print(" " + String.format(formatStr, vec.get(i)) + ((i != slot_count - 1) ? "," : " ]\n"));
            }
        }
        System.out.println();
    }
    public static double log2(double N) {
        return Math.log(N)/Math.log(2);//Math.log的底为e
    }
    //public static void main(String[] args) {
    //    System.out.println("##byte to hex:"+byteToHex(new byte[]{3}));
    //}
}
