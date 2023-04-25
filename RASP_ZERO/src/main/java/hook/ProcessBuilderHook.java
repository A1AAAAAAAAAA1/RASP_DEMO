// 在transform中执行类转换的逻辑，插入过滤代码
package hook;

import javassist.*;

import java.io.IOException;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

public class ProcessBuilderHook implements ClassFileTransformer {
    private Instrumentation inst;
    private ClassPool classPool;
    public ProcessBuilderHook(Instrumentation inst){
        this.inst = inst;
        this.classPool = new ClassPool(true);
    }

    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) {
        if (className.equals("java/lang/ProcessBuilder")){
            CtClass ctClass = null;
            try {
                // 找到ProcessBuilder对应的字节码
                ctClass = this.classPool.get("java.lang.ProcessBuilder");
                // 获取所有method
                CtMethod[] methods = ctClass.getMethods();
                // $0代表this，这里this = 用户创建的ProcessBuilder实例对象
                String src = "System.out.println(\"接收到的ProcessBulider实例对象:\"+$0.command);"+
                        "if ($0.command.get(0).equals(\"cmd\"))" +
                        "{System.out.println(\"检测到危险命令\");\n" +
                        "System.out.println(\"RASP_ZERO  将阻断危险命令执行！！！\");\n"+
                        "            System.out.println(\"\\n\");       "+
                        "return null;}";
                for (CtMethod method : methods) {
                    // 找到start方法，并插入拦截代码
                    if (method.getName().equals("start")){
                        method.insertBefore(src);
                        break;
                    }
                }
                classfileBuffer = ctClass.toBytecode();
            }
            catch (NotFoundException | CannotCompileException | IOException e) {
                e.printStackTrace();
            }
            finally {
                if (ctClass != null){
                    ctClass.detach();
                }
            }
        }
        return classfileBuffer;
    }
}
