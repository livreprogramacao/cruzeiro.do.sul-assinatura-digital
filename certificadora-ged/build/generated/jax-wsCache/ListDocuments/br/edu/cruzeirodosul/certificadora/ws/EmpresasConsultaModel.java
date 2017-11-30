
package br.edu.cruzeirodosul.certificadora.ws;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Classe Java de empresasConsultaModel complex type.
 * 
 * <p>O seguinte fragmento do esquema especifica o conteúdo esperado contido dentro desta classe.
 * 
 * <pre>
 * &lt;complexType name="empresasConsultaModel">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="codigoEmpresa" type="{http://www.w3.org/2001/XMLSchema}int" minOccurs="0"/>
 *         &lt;element name="nomeEmpresa" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="nomeAbreviado" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="codigoTipoEnsino" type="{http://www.w3.org/2001/XMLSchema}int" minOccurs="0"/>
 *         &lt;element name="descricaoTipoEnsino" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "empresasConsultaModel", propOrder = {
    "codigoEmpresa",
    "nomeEmpresa",
    "nomeAbreviado",
    "codigoTipoEnsino",
    "descricaoTipoEnsino"
})
public class EmpresasConsultaModel {

    protected Integer codigoEmpresa;
    protected String nomeEmpresa;
    protected String nomeAbreviado;
    protected Integer codigoTipoEnsino;
    protected String descricaoTipoEnsino;

    /**
     * Obtém o valor da propriedade codigoEmpresa.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public Integer getCodigoEmpresa() {
        return codigoEmpresa;
    }

    /**
     * Define o valor da propriedade codigoEmpresa.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setCodigoEmpresa(Integer value) {
        this.codigoEmpresa = value;
    }

    /**
     * Obtém o valor da propriedade nomeEmpresa.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getNomeEmpresa() {
        return nomeEmpresa;
    }

    /**
     * Define o valor da propriedade nomeEmpresa.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setNomeEmpresa(String value) {
        this.nomeEmpresa = value;
    }

    /**
     * Obtém o valor da propriedade nomeAbreviado.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getNomeAbreviado() {
        return nomeAbreviado;
    }

    /**
     * Define o valor da propriedade nomeAbreviado.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setNomeAbreviado(String value) {
        this.nomeAbreviado = value;
    }

    /**
     * Obtém o valor da propriedade codigoTipoEnsino.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public Integer getCodigoTipoEnsino() {
        return codigoTipoEnsino;
    }

    /**
     * Define o valor da propriedade codigoTipoEnsino.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setCodigoTipoEnsino(Integer value) {
        this.codigoTipoEnsino = value;
    }

    /**
     * Obtém o valor da propriedade descricaoTipoEnsino.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getDescricaoTipoEnsino() {
        return descricaoTipoEnsino;
    }

    /**
     * Define o valor da propriedade descricaoTipoEnsino.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setDescricaoTipoEnsino(String value) {
        this.descricaoTipoEnsino = value;
    }

}
