package hook;

import javassist.*;

import java.io.IOException;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

public class RuntimeHook implements ClassFileTransformer {
    //声明一个Instrumentation 与ClassPool,设置为类中私有的变量
    private Instrumentation inst;
    private ClassPool classPool;
    public RuntimeHook(Instrumentation inst) {
        this.inst =inst;
        this.classPool = new ClassPool(true);
    }

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {
        if (className.equals("java/lang/Runtime")){
            CtClass ctClass = null;
//            System.out.println("RASP_ZERO将阻断该命令的执行");
            //检查规则
            String src ="        while($1!=null){\n" +
                    "            System.out.println(\"RASP_ZERO将执行监控\");\n" +
                    "            System.out.println(\"成功抓取到JAVA Runtime.exec()exec()方法\");\n" +
                    "            System.out.println(\"抓取到的输入为:\"+$1);\n" +
                    "              System.out.println(\"RASP_ZERO将阻断该命令的执行\");" +
                    "            System.out.println(\"\\n\");       "+
                    "            return null;\n" +
                    "        }";
//  使用$1(javassist语法)成功获取入参          String src="System.out.println($1);";
//            String src ="System.out.println(\"命令执行参数为:\"+ $0.exec.get(0));";
            try{
                //找到Runtime()类对应的字节码
                ctClass = this.classPool.get("java.lang.Runtime");

                //直接抓取方法
                CtMethod ctMethod =ctClass.getDeclaredMethod("exec");
//                System.out.println(ctMethod.isEmpty());
//                System.out.println(ctMethod.getMethodInfo());
//                ctMethod.insertBefore("System.out.println(\"所有输入为:\"+$0);");
                ctMethod.insertBefore(src);

                //获取所有method
//                CtMethod[] methods = ctClass.getMethods();
//                for (CtMethod method : methods){
////                    System.out.println(method.getDeclaringClass());
////                    System.out.println(method.getName());
////                    找到exec方法，并插入检测代码
//                    if (method.get.equals("exec")){
//                        System.out.println("匹配到exec方法");
////                        method.insertBefore(src);
////                        break;
//                    }
//                }
                classfileBuffer =ctClass.toBytecode();
                //$0代表this，这里this = 用户创建的ProcessBuilder实例对象
            } catch (NotFoundException | CannotCompileException | IOException e) {
                e.printStackTrace();
            }
            finally {
                if(ctClass !=null){
                    ctClass.detach();
                }
            }
        }
        return  classfileBuffer;
    }
}


