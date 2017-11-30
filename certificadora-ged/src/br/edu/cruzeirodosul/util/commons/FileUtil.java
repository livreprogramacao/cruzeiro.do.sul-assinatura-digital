package br.edu.cruzeirodosul.util.commons;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.channels.FileChannel;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Classe
 *
 * @author Jefferson Rago - jefferson.rago@cruzeirodosul.edu.br
 *
 */
public class FileUtil {

    static final File DIRETORIO_TEMP_UNIX = new File("/media/filemanager/temp/certificacao");
    static final File DIRETORIO_TEMP_WINDOWS = new File("C:\\temp\\certificacao");

    /**
     * Método para verificar a extenção do arquivo
     *
     * @param file
     * @return
     * @throws Exception
     */
    public static String extentionFile(String file) throws Exception {
        String ext[] = file.split("\\.");
        int i = ext.length;

        if (i > 1) {
            return ext[i - 1];
        } else {
            throw new Exception("Nenhuma extensão foi localizada!");
        }
    }

    /**
     * Método para gerar um arquivo através da URL
     *
     * @param path
     * @return
     * @throws Exception
     */
    public static File getFileByUrl(String path) throws Exception {
        File fileTemp = null;
        HttpURLConnection huc = null;
        OutputStream outputStream = null;

        String caminhoURL = "https://sistemas.cruzeirodosul.edu.br";

        URL urlLink = new URL(caminhoURL + path);
        huc = (HttpURLConnection) urlLink.openConnection();
        huc.setRequestMethod("GET");

        if (huc.getResponseCode() == 200) {
            //System.out.println("[FILEUTIL] Arquivo localizado");
            InputStream in = huc.getInputStream();
            String nomeFile = (new SimpleDateFormat("ddMMyyyy-HHmmssSSS").format(new Date())) + "." + extentionFile(path);

            if (System.getProperty("os.name").toLowerCase().contains("windows")) {
                if (!DIRETORIO_TEMP_WINDOWS.exists()) {
                    DIRETORIO_TEMP_WINDOWS.mkdirs();
                }
                fileTemp = new File(DIRETORIO_TEMP_WINDOWS + "/" + nomeFile);

            } else {
                if (!DIRETORIO_TEMP_UNIX.exists()) {
                    DIRETORIO_TEMP_UNIX.mkdirs();
                }
                fileTemp = new File(DIRETORIO_TEMP_UNIX + "/" + nomeFile);
            }

            outputStream = new FileOutputStream(fileTemp);

            int read = 0;
            byte[] bytes = new byte[1024];

            while ((read = in.read(bytes)) != -1) {
                outputStream.write(bytes, 0, read);
            }

            outputStream.close();
            in.close();

            if (huc != null) {
                huc.disconnect();
            }

            if (fileTemp.exists()) {
                return fileTemp;
            } else {
                throw new Exception("Não foi possível gerar o arquivo: " + fileTemp.getAbsolutePath());
            }
        }

        return null;
    }

    /**
     * Método para Mover/Cópia ou concatenação arquivos
     *
     * @param source Arquivo base
     * @param destination Arquivo de destino
     * @param overwrite Substituir arquivo
     * @param copy Copia do arquivo - false: Mover Arquivo; true: Cópiar Arquivo
     * @param concatenate
     *
     * <b>Regra de concatenação:</b>
     * Para realizar concatenação de arquivo é necessário que o <b>overwrite</b>
     * = true e <b>concatenate</b> = true
     * @since 30/10/2015
     */
    public static boolean moveFile(File source, File destination, boolean overwrite, boolean copy, boolean concatenate) throws Exception {
        System.out.println((copy ? "Copiando" : "Movendo") + " o arquivo " + source.toString() + " para " + destination.toString());

        File diretorio = new File(destination.toString().replace(destination.getName(), ""));
        Date date = new Date();
        Long time = new Date().getTime() - date.getTime();

        // Verifica se o diretorio de destino existe, caso não existe ele cria
        if (!diretorio.exists()) {
            diretorio.mkdirs();
        }

        // Verifica se o arquivo destinario existe e se não é para realizar a substituição do arquivo
        if (destination.exists() && !overwrite) {
            throw new Exception("O arquivo " + destination.getName() + " já existe, ignorando...");
        }

        // Verifica se o arquivo destino não existe e se não é para realizar a concatenação
        //System.out.println("Verificando se o arquivo existe: " + destination.exists() + " - " + destination.toString());
        if (!destination.exists() && !concatenate) {
            FileInputStream fisOrigem = new FileInputStream(source);
            FileOutputStream fisDestino = new FileOutputStream(destination);
            FileChannel fcOrigem = fisOrigem.getChannel();
            FileChannel fcDestino = fisDestino.getChannel();
            fcOrigem.transferTo(0, fcOrigem.size(), fcDestino);
            fisOrigem.close();
            fisDestino.close();
        } else {
            throw new Exception("Opção não é validação, por favor, verifique a documentação do método");
        }

        // Verifica se é para excluir o arquivo base
        if (source.exists() && source.isFile() && !copy) {
            source.delete();
            //System.out.println("Arquivo base " + source.toString() + " foi excluindo!");
        }

        //System.out.println("Finalizou a transferencia do arquivo " + time);
        return true;
    }

}
