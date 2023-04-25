import hook.*;

import java.lang.instrument.Instrumentation;
import java.lang.instrument.UnmodifiableClassException;
import java.util.HashMap;

public class Premain {
    public static HashMap<String,Object> Hookclass(){
        //创建 HashMap 对象Sites
        HashMap<String,Object> Sites =new HashMap<String,Object>();
        Sites.put("展示所有类（默认不开启）","showAll");
        Sites.put("检测ProcessBulider命令执行","processBuilderHook");
        Sites.put("检测Runtime命令执行","runtimeHook");
        Sites.put("检测Mysql Statementsql注入","sqlhook");
        Sites.put("检测DocumentBuilderFactory XXE","xmlSqlHook");
        System.out.println("目前hook的方法数量:"+Sites.size()+"种");
        int node=1;
        for (String key : Sites.keySet()) {
            System.out.println("方法"+node+":");
            System.out.println("作用:"+key);
            System.out.println("实现方法:"+Sites.get(key));
            node++;
        }
        return Sites;
    }
    public static void premain(String agentArgs, Instrumentation inst) throws UnmodifiableClassException {
        Premain.Tip();
        HashMap<String,Object> Hooks=Premain.Hookclass();
        //添加ClassFileTransformer类
        ShowAll showAll = new ShowAll();
        ProcessBuilderHook processBuilderHook =new ProcessBuilderHook(inst);
        RuntimeHook runtimeHook = new RuntimeHook(inst);
        SqlHook sqlhook = new SqlHook(inst);
        XmlSqlHook xmlSqlHook = new XmlSqlHook(inst);
        try {
            System.out.println("\u001b[1;37m…………………………………………………………开始加载类转换器…………………………………………………………"+"\n\u001b[0m");

//            try {
////                默认不启动，如需启动将将注释取消
//                inst.addTransformer(showAll, true);
//            } catch (Exception e) {
//                e.printStackTrace();
//            }
            try {
                System.out.println("\u001b[1;37m………………………………………………………开始加载processBuilderHook…………………………………"+"\n\u001b[0m");
                inst.addTransformer(processBuilderHook,true);
            } catch (Exception e) {
                e.printStackTrace();
            }System.out.println("\u001b[1;32m成功加载processBuilderHook！！！！！！"+"\n\u001b[0m");
            try {
                System.out.println("\u001b[1;37m………………………………………………………开始加载runtimeHook……………………………………………………"+"\n\u001b[0m");
                inst.addTransformer(runtimeHook,true);
            } catch (Exception e) {
                e.printStackTrace();
            }System.out.println("\u001b[1;32m成功加载runtimeHook！！！！！！"+"\n\u001b[0m");
            try {
                System.out.println("\u001b[1;37m………………………………………………………开始加载sqlhook………………………………………………………………"+"\n\u001b[0m");
                inst.addTransformer(sqlhook, true);
            } catch (Exception e) {
                e.printStackTrace();
            }System.out.println("\u001b[1;32m成功加载sqlhook！！！！！！"+"\n\u001b[0m");
            try {
                System.out.println("\u001b[1;37m………………………………………………………开始加载xmlSqlHook………………………………………………………"+"\n\u001b[0m");
                inst.addTransformer(xmlSqlHook, true);
            } catch (Exception e) {
                e.printStackTrace();
            }System.out.println("\u001b[1;32m成功加载xmlSqlHook！！！！！！"+"\n\u001b[0m");
        } catch (Exception e) {
            e.printStackTrace();
        }


        //加入到ClassLoader类加载器中
        Class[] allLoadedClasses = inst.getAllLoadedClasses();
        for (Class aClass : allLoadedClasses) {
            if (inst.isModifiableClass(aClass) && !aClass.getName().startsWith("java.lang.invoke.LambdaForm")) {
                //调用instrumentation中所有的ClassFileTransformer#transform方法，实现类字节码修改
                inst.retransformClasses(new Class[]{aClass});
            }
        }
        System.out.println("\u001b[1;32m已完成以上所有Hook，Rasp_zero运行成功\u001b[0m");
    }
    public static void  Tip(){
        System.out.println("\u001b[1;36m \n" +
                "               ^       **                                               @**\n" +
                "   *****^     ***     *****  *****           ******  *****@ ******     *****\n" +
                "   ******     ***    ******  ******          ******  *****@ *******   *******\n" +
                "   **  **@    ***    **   *  **  **              **  **     **  ^**   **   ***\n" +
                "   **  @**   ** **   **      **  ***            ***  **     **   **  ***   ***\n" +
                "   **   **   ** **   **      **   **            **   **     **   **  **     **\n" +
                "   **  @**   ** **   ***     **  ^**           ***   **     **   **  **     **\n" +
                "   **  **    ** **   ****    **  **            **    *****  **  ***  **     **\n" +
                "   ******    *  **    ****   **  **            **    *****  ******   **     **\n" +
                "   *****    **  @**    ****  ******           ***    *****  *****^   **     **\n" +
                "    ** ***   **   **     ***  *****            **     **     **  **   **     **\n" +
                "   **  **   *******      **  **              ^**     **     **  ***  **     **\n" +
                "   **  **   *******      **  **              **      **     **   **  **     **\n" +
                "   **  **^ **    ***     **  **              **      **     **   **  ***   ***\n" +
                "   **   ** **    ^** **@***  **             *******  *****  **   **   *******\n" +
                "   **   ** **     ** ******  **             *******  ****** **   ***  *******\n" +
                "   **   ** **     ** *****   ** ********  ^******  *****@ **    **   *****\u001b[0m" +
                "                                   \u001b[1;32m@Author:A1AAAAAAAAAA1 by 2023/4\u001b[0m");
//        System.out.println("\u001b[1;32m@Author:A1AAAAAAAAAA1 by 2023/4\u001b[0m");

        System.out.println("\u001b[1;32mRasp_zero开始启动，请稍等。。。\u001b[0m");
    }


}
