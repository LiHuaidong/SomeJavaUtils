package hdli.utils;

import java.io.DataInput;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;

import org.gjt.jclasslib.io.ClassFileWriter;
import org.gjt.jclasslib.structures.AttributeInfo;
import org.gjt.jclasslib.structures.CPInfo;
import org.gjt.jclasslib.structures.ClassFile;
import org.gjt.jclasslib.structures.MethodInfo;
import org.gjt.jclasslib.structures.constants.ConstantUtf8Info;

public class ClassModification {

	public static void main(String[] args) throws Exception {
		String filePath = "C:\\Users\\HDLI\\Desktop\\新建文件夹\\jar\\Version2LicenseDecoder.class";
		FileInputStream fis = new FileInputStream(filePath);
		
		DataInput di = new DataInputStream(fis);
		ClassFile cf = new ClassFile();
		cf.read(di);
		CPInfo[] infos = cf.getConstantPool();
		int length = infos.length;
		for(int i=0; i<length; i++) {
			if(infos[i] != null) {
				System.out.print(i);
				System.out.print(" = ");
				System.out.print(infos[i].getVerbose());
				System.out.print(" = ");
				System.out.println(infos[i].getTagVerbose());
				if(i == 270) {
					ConstantUtf8Info uInfo = (ConstantUtf8Info) infos[i];
					uInfo.setString("test");
					infos[i] = uInfo;
				}
			}
		}
		cf.setConstantPool(infos);
		fis.close();
		File f = new File(filePath);
		ClassFileWriter.writeToFile(f, cf);
	}

}
