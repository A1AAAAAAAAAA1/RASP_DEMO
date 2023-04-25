package hook;

import javassist.*;

import java.io.IOException;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

public class XmlSqlHook implements ClassFileTransformer {
    //声明一个Instrumentation 与ClassPool,设置为类中私有的变量
    private Instrumentation inst;
    private ClassPool classPool;

    public XmlSqlHook(Instrumentation inst) {
        this.inst = inst;
        this.classPool = new ClassPool(true);
    }

    /**
     * 对使用DocumentBuilderFactory类解析xml格式数据可能产生的xxe(外部实体注入)进行hook
     * 注:当前解决xxe的常用方法一般是禁用外部实体，本项目只是对XXE漏洞及Rasp技术做研究
     * 使用Rasp可实现对xml解析情况的监控，外部代码无感知
     */

    //需要抓取的类 javax.xml.parsers.DocumentBuilder
    //类方法 parse(File f)
    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {
        if (className.equals("com/sun/org/apache/xerces/internal/jaxp/DocumentBuilderImpl")){
//            System.out.println(className);
//            System.out.println("aaa");

            CtClass ctClass = null;
            try {
                ctClass =this.classPool.get("com.sun.org.apache.xerces.internal.jaxp.DocumentBuilderImpl");
//                System.out.println(ctClass.getName());
                //获取类中所有字段
//                CtField[] fields=ctClass.getDeclaredFields();
//                for (CtField field :fields){
//                    System.out.println("字段为:"+field.getName());
//                }
                /**
                 * 拦截规则
                 * 定义parse()对象接收的数据的处理方法
                 * 检测到parse()方法接收到的参数为org.xml.sax.InputSource类时
                 * 输出参数类型值并阻断
                 * 此代码相当于关闭了外部实体的引入，如正常业务需要接收外部的Xml处理，则要关闭此Hook
                 */

                String src ="        if($1.toString().contains(\"org.xml.sax.InputSource\")){\n" +
                        "            System.out.println(\"外部实体对象内存指针为:\"+$1);\n"+
                        "            System.out.println(\"检测到外部实体的引用！！！\");\n" +
                        "            System.out.println(\"RASP_Zero  将阻断parse()方法解析！！！\");\n  " +
                        "            System.out.println(\"\\n\");       "+
                        "            return null;}";

//                String src="System.out.println(\"抓取到的输入为:\"+$2);";
//                //直接抓取方法
//                CtMethod ctMethod = ctClass.getDeclaredMethod("parse");
//                CtMethod ctMethod = ctClass.getDeclaredMethod("parse");
//                CtField[] fields=ctClass.getDeclaredFields();
                CtMethod[] methods = ctClass.getMethods();
                for (CtMethod method : methods) {
//                    System.out.println(method.getName());
                    if (method.getName().equals("parse")) {
//                        System.out.println(11121);
//                        System.out.println(method.getReturnType());
//                        System.out.println(method.getLongName());
//                        System.out.println(method.getMethodInfo());
//                        MethodInfo methodInfo =method.getMethodInfo();
//                        boolean isStatic = (methodInfo.getAccessFlags() & AccessFlag.STATIC) != 0;
////                        System.out.println(isStatic); false 不为静态方法
//                        CodeAttribute codeAttribute = methodInfo.getCodeAttribute();
//                        LocalVariableAttribute attr = (LocalVariableAttribute) codeAttribute.getAttribute(LocalVariableAttribute.tag);
//                        CtClass[] parameterTypes = method.getParameterTypes();
//                        CtClass returnType = method.getReturnType();
//                        String returnTypeName = returnType.getName();

//                        System.out.println("类型：" + (isStatic ? "静态方法" : "非静态方法"));
//                        System.out.println("描述：" + methodInfo.getDescriptor());
//                        System.out.println("入参[名称]：" + attr.variableName(1) + "，" + attr.variableName(2));
//                        System.out.println("入参[类型]：" + parameterTypes[0].getName() + "，" + parameterTypes[1].getName());
//                        System.out.println("出参[类型]：" + returnTypeName);
                        method.insertBefore(src);
//                        method.insertBefore("{System.out.println(\"抓取参数为:\"+$1);}");

                    }
                }


                classfileBuffer =ctClass.toBytecode();
            } catch (NotFoundException | CannotCompileException | IOException e) {
                e.printStackTrace();
            } finally {
                if(ctClass !=null){
                    ctClass.detach();
                }
            }
        }
        return classfileBuffer;
    }
}