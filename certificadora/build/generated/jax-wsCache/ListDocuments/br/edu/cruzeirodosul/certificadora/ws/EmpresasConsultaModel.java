
package br.edu.cruzeirodosul.certificadora.ws;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for empresasConsultaModel complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
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
     * Gets the value of the codigoEmpresa property.
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
     * Sets the value of the codigoEmpresa property.
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
     * Gets the value of the nomeEmpresa property.
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
     * Sets the value of the nomeEmpresa property.
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
     * Gets the value of the nomeAbreviado property.
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
     * Sets the value of the nomeAbreviado property.
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
     * Gets the value of the codigoTipoEnsino property.
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
     * Sets the value of the codigoTipoEnsino property.
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
     * Gets the value of the descricaoTipoEnsino property.
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
     * Sets the value of the descricaoTipoEnsino property.
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
