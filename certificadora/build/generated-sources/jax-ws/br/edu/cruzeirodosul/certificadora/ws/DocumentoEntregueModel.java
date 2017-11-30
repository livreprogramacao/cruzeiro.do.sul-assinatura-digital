
package br.edu.cruzeirodosul.certificadora.ws;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.datatype.XMLGregorianCalendar;


/**
 * <p>Java class for documentoEntregueModel complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="documentoEntregueModel">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="codigoInstituicao" type="{http://www.w3.org/2001/XMLSchema}int" minOccurs="0"/>
 *         &lt;element name="rgmAluno" type="{http://www.w3.org/2001/XMLSchema}long" minOccurs="0"/>
 *         &lt;element name="nomeAluno" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="codigoDocumento" type="{http://www.w3.org/2001/XMLSchema}int" minOccurs="0"/>
 *         &lt;element name="nomeDocumento" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="sequencioDocumentos" type="{http://www.w3.org/2001/XMLSchema}int" minOccurs="0"/>
 *         &lt;element name="idArquivo" type="{http://www.w3.org/2001/XMLSchema}long" minOccurs="0"/>
 *         &lt;element name="caminhoArquivo" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="nomeArquivo" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="extensaoArquivo" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="dataBaixa" type="{http://www.w3.org/2001/XMLSchema}dateTime" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "documentoEntregueModel", propOrder = {
    "codigoInstituicao",
    "rgmAluno",
    "nomeAluno",
    "codigoDocumento",
    "nomeDocumento",
    "sequencioDocumentos",
    "idArquivo",
    "caminhoArquivo",
    "nomeArquivo",
    "extensaoArquivo",
    "dataBaixa"
})
public class DocumentoEntregueModel {

    protected Integer codigoInstituicao;
    protected Long rgmAluno;
    protected String nomeAluno;
    protected Integer codigoDocumento;
    protected String nomeDocumento;
    protected Integer sequencioDocumentos;
    protected Long idArquivo;
    protected String caminhoArquivo;
    protected String nomeArquivo;
    protected String extensaoArquivo;
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar dataBaixa;

    /**
     * Gets the value of the codigoInstituicao property.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public Integer getCodigoInstituicao() {
        return codigoInstituicao;
    }

    /**
     * Sets the value of the codigoInstituicao property.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setCodigoInstituicao(Integer value) {
        this.codigoInstituicao = value;
    }

    /**
     * Gets the value of the rgmAluno property.
     * 
     * @return
     *     possible object is
     *     {@link Long }
     *     
     */
    public Long getRgmAluno() {
        return rgmAluno;
    }

    /**
     * Sets the value of the rgmAluno property.
     * 
     * @param value
     *     allowed object is
     *     {@link Long }
     *     
     */
    public void setRgmAluno(Long value) {
        this.rgmAluno = value;
    }

    /**
     * Gets the value of the nomeAluno property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getNomeAluno() {
        return nomeAluno;
    }

    /**
     * Sets the value of the nomeAluno property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setNomeAluno(String value) {
        this.nomeAluno = value;
    }

    /**
     * Gets the value of the codigoDocumento property.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public Integer getCodigoDocumento() {
        return codigoDocumento;
    }

    /**
     * Sets the value of the codigoDocumento property.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setCodigoDocumento(Integer value) {
        this.codigoDocumento = value;
    }

    /**
     * Gets the value of the nomeDocumento property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getNomeDocumento() {
        return nomeDocumento;
    }

    /**
     * Sets the value of the nomeDocumento property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setNomeDocumento(String value) {
        this.nomeDocumento = value;
    }

    /**
     * Gets the value of the sequencioDocumentos property.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public Integer getSequencioDocumentos() {
        return sequencioDocumentos;
    }

    /**
     * Sets the value of the sequencioDocumentos property.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setSequencioDocumentos(Integer value) {
        this.sequencioDocumentos = value;
    }

    /**
     * Gets the value of the idArquivo property.
     * 
     * @return
     *     possible object is
     *     {@link Long }
     *     
     */
    public Long getIdArquivo() {
        return idArquivo;
    }

    /**
     * Sets the value of the idArquivo property.
     * 
     * @param value
     *     allowed object is
     *     {@link Long }
     *     
     */
    public void setIdArquivo(Long value) {
        this.idArquivo = value;
    }

    /**
     * Gets the value of the caminhoArquivo property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getCaminhoArquivo() {
        return caminhoArquivo;
    }

    /**
     * Sets the value of the caminhoArquivo property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setCaminhoArquivo(String value) {
        this.caminhoArquivo = value;
    }

    /**
     * Gets the value of the nomeArquivo property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getNomeArquivo() {
        return nomeArquivo;
    }

    /**
     * Sets the value of the nomeArquivo property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setNomeArquivo(String value) {
        this.nomeArquivo = value;
    }

    /**
     * Gets the value of the extensaoArquivo property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getExtensaoArquivo() {
        return extensaoArquivo;
    }

    /**
     * Sets the value of the extensaoArquivo property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setExtensaoArquivo(String value) {
        this.extensaoArquivo = value;
    }

    /**
     * Gets the value of the dataBaixa property.
     * 
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public XMLGregorianCalendar getDataBaixa() {
        return dataBaixa;
    }

    /**
     * Sets the value of the dataBaixa property.
     * 
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public void setDataBaixa(XMLGregorianCalendar value) {
        this.dataBaixa = value;
    }

}
