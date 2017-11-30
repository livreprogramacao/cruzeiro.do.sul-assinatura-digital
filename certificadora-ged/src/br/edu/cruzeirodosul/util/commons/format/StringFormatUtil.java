/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package br.edu.cruzeirodosul.util.commons.format;

/**
 *
 * @author Administrador
 */
public class StringFormatUtil {
    
    /**
     * Recebe uma String e Retorna True se for null ou vazia
     *
     * @param dado
     * @return
     */
    public static boolean isNull(String dado) {
        if (dado == null) {
            return true;
        }

        dado = dado.trim();
        if (dado.equals("")) {
            return true;
        }

        if (dado.equalsIgnoreCase("null")) {
            return true;
        }
        return false;
    }
    
    /**
     * RECEBE UM VALOR SE FOR NULO RETORNA A ALTERNATIVA
     *
     * @param valor (STRING A VERIFICAR)
     * @param novo (STRING ALTERNATIVA)
     * @return
     */
    public static String trataNulo(String valor, String novo) {
        if (isNull(valor)) {
            return novo;
        }
        return valor;
    }
    

}
