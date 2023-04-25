package hook;

import javassist.*;

import java.io.IOException;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

public class SqlHook implements ClassFileTransformer {
    //声明一个Instrumentation 与ClassPool,设置为类中私有的变量
    private Instrumentation inst;
    private ClassPool classPool;

    public SqlHook(Instrumentation inst) {
        this.inst = inst;
        this.classPool = new ClassPool(true);
    }

    //对sql语句进行执行的类进行Hook
    //通过查看百度Rasp源码，得知jdbc执行statement查询的类名为:com/mysql/jdbc/StatementImpl或com/mysql/cj/jdbc/StatementImpl
    //com.mysql.jdbc.Driver是mysql-connector-java 5中的，而com.mysql.cj.jdbc.Driver是mysql-connector-java 6中
    //本此使用的是5
    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {
        if (className.equals("com/mysql/jdbc/StatementImpl")) {
            CtClass ctClass = null;
            try {
                //找到 StatementImpl 对应的字节码
                ctClass = this.classPool.get("com.mysql.jdbc.StatementImpl");
                //获取所有method
                /**
                 *         需要Hook的代码
                 *         String sql ="select flag from sql_rasp where sql_test=1 or 1=1";
                 *         Statement stmt =conn.createStatement();
                 *
                 *         ResultSet rs =stmt.executeQuery(sql);
                 */
//                String src = "if ($1.substring(971).contains(\"or\"))" +
//                        "{System.out.println(\"危险,检测到sql注入!\");" +
//                        "System.out.println();"+
//                        "return null;}";
                String src ="        if($1.contains(\"=\")) {\n" +
                        "            System.out.println(\"RASP_ZERO目前只通过正则匹配sql注入攻击\" );\n" +
                        "            System.out.println(\"接收到sql语句\");\n" +
                        "            System.out.println(\"RASP_ZERO将执行监控\");\n" +
                        "            String pattern0 = \"^.*?=(.*)$\";\n" +
                        "            String replacement = \"$1\";\n" +
                        "            System.out.println();\n" +
                        "            String sql = $1.replaceAll(pattern0, replacement);\n" +
                        "            System.out.println(\"sql语句为:\" + sql);\n" +
                        "             if (sql!=null) {\n" +
                        "            String regex = \"(?i)\\\\b(select|order|by|information_schema|outfile|dumpfile|load_file|benchmark|pg_sleep|sleep|is_srvrolemember|updatexml|extractvalue|hex|char|chr|mid|ord|ascii|bin|or)\\\\b\";" +
                        "            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(regex);\n" +
                        "            java.util.regex.Matcher matcher = pattern.matcher(sql);\n" +
                        "            while (matcher.find()) {\n" +
                        "                System.out.println(\"检测到危险字符,RASP_ZERO将阻断此sql语句的执行\");\n" +
                        "                return null;\n" +
                        "            }\n" +
                        "        }\n" +
                        "        }";

//                String src = "if ($1.contains(\"or\"))" +
//                        "{System.out.println(\"危险,检测到sql注入!\");" +
//                        "System.out.println();"+
//                        "return null;}";
//                String src ="System.out.println(executeQuery.outParameterQuery.toString());";
                // 获取所有method
                CtMethod[] methods = ctClass.getMethods();

                for (CtMethod method : methods) {
                    // 找到executeQuery方法，并插入拦截代码
                    if (method.getName().equals("executeQuery")) {
                        method.insertBefore(src);
                        break;
                    }
                    //方法信息
                }
                        // 获取字段
//                        method.insertBefore(src);
//                    break;
                //字节码转换
                classfileBuffer = ctClass.toBytecode();
            } catch (NotFoundException | CannotCompileException | IOException e) {
                e.printStackTrace();
            }

        }

        //如果判断存在恶意语句，则进行拦截
        //使用javassist 对字节码进行增强(修改)
        return classfileBuffer;
    }
}