/*
 * Copyright (c) 2018. Punch Cyber Analytics Group
 * All rights reserved.
 *
 * NOTICE: All information contained herein is the property of Punch Cyber Analytics Group.
 * The intellectual and technical concepts contained herein are proprietary to Punch Cyber
 * Analytics Group and may be covered by Patents and/or Patents in process in multiple
 * jurisdictions and as such, are protected by trade secret and/or copyright laws.
 *
 * Neither reproduction or dissemination of this material is permitted without prior written
 * permission from Punch Cyber Analytics Group
 */

package com.punchcyber.pakhet.datatypes.evtx

import java.io.IOException
import java.util

import org.apache.nifi.processors.evtx.parser.BxmlNodeVisitor
import org.apache.nifi.processors.evtx.parser.bxml._
import org.apache.nifi.processors.evtx.parser.bxml.value.{BXmlTypeNode, VariantTypeNode}

import scala.collection.mutable

class EvtxNodeVisitor extends BxmlNodeVisitor {
  val substitutions: util.LinkedList[VariantTypeNode] = new util.LinkedList[VariantTypeNode]()
  var event: mutable.LinkedHashMap[String,(String,String)] = new mutable.LinkedHashMap[String,(String,String)]()

  def this(rootNode: RootNode,ef: mutable.LinkedHashMap[String,(String,String)] = new mutable.LinkedHashMap[String,(String,String)]()) {
    this
    substitutions.addAll(rootNode.getSubstitutions)

    event = ef

    rootNode.getChildren.forEach(node => {
      node.accept(this)
    })
  }

  var sectionName: String = "Event"
  var tagName: String = _
  var attName: String = ""
  var key: String = ""
  var value: String = ""

  @throws[IOException]
  override def visit(node: OpenStartElementNode): Unit = {
    val children: util.List[BxmlNode] = node.getChildren

    children.forEach(child => {

      child.accept(this)
      if(Array("System","EventData").contains(node.getTagName)) sectionName = node.getTagName
      tagName = node.getTagName

      child match {
        case cv: AttributeNode =>
          val childValue = cv.asInstanceOf[AttributeNode].getValue
          attName = cv.asInstanceOf[AttributeNode].getAttributeName

          childValue match {
            case _: ValueNode =>
              val attributeName: String = child.asInstanceOf[AttributeNode].getAttributeName
              val attributeValue: String = childValue.asInstanceOf[ValueNode].getChildren.get(0).asInstanceOf[VariantTypeNode].getValue

              if(attributeName.equals("Name")) {
                key = attributeValue
              }

            case _: NormalSubstitutionNode =>
              event += (f"${sectionName.toUpperCase}_${tagName.toUpperCase}_${attName.toUpperCase}" -> (substitutions.get(childValue.asInstanceOf[NormalSubstitutionNode].getIndex).getValue.stripLineEnd,substitutions.get(childValue.asInstanceOf[NormalSubstitutionNode].getIndex).getClass.getSimpleName))
            case _: ConditionalSubstitutionNode =>
              event += (f"${sectionName.toUpperCase}_${tagName.toUpperCase}_${attName.toUpperCase}" -> (substitutions.get(childValue.asInstanceOf[ConditionalSubstitutionNode].getIndex).getValue.stripLineEnd,substitutions.get(childValue.asInstanceOf[ConditionalSubstitutionNode].getIndex).getClass.getSimpleName))
            case _ =>
          }
        case _: NormalSubstitutionNode =>
          if(substitutions.get(child.asInstanceOf[NormalSubstitutionNode].getIndex).isInstanceOf[VariantTypeNode] &&
            !substitutions.get(child.asInstanceOf[NormalSubstitutionNode].getIndex).isInstanceOf[BXmlTypeNode]) {

            event += (f"${sectionName.toUpperCase}_${tagName.toUpperCase}_${key.toUpperCase}" -> (substitutions.get(child.asInstanceOf[NormalSubstitutionNode].getIndex).getValue.stripLineEnd,substitutions.get(child.asInstanceOf[NormalSubstitutionNode].getIndex).getClass.getSimpleName))
          }
          else if(!key.equals("")) {
            event += (f"${sectionName.toUpperCase}_${key.toUpperCase}" -> (substitutions.get(child.asInstanceOf[NormalSubstitutionNode].getIndex).getValue.stripLineEnd,substitutions.get(child.asInstanceOf[NormalSubstitutionNode].getIndex).getClass.getSimpleName))
          }
        case _: ConditionalSubstitutionNode =>
          if(substitutions.get(child.asInstanceOf[ConditionalSubstitutionNode].getIndex).isInstanceOf[VariantTypeNode] &&
            !substitutions.get(child.asInstanceOf[ConditionalSubstitutionNode].getIndex).isInstanceOf[BXmlTypeNode]) {

            event += (f"${sectionName.toUpperCase}_${tagName.toUpperCase}" -> (substitutions.get(child.asInstanceOf[ConditionalSubstitutionNode].getIndex).getValue.stripLineEnd,substitutions.get(child.asInstanceOf[ConditionalSubstitutionNode].getIndex).getClass.getSimpleName))
          }
          else if(!key.equals("")) {
            event += (f"${sectionName.toUpperCase}_${tagName.toUpperCase}" -> (substitutions.get(child.asInstanceOf[ConditionalSubstitutionNode].getIndex).getValue.stripLineEnd,substitutions.get(child.asInstanceOf[ConditionalSubstitutionNode].getIndex).getClass.getSimpleName))
          }
        case _: ValueNode =>
          event += (f"${sectionName.toUpperCase}_${tagName.toUpperCase}" -> (child.getChildren.get(0).asInstanceOf[VariantTypeNode].getValue.stripLineEnd,child.getChildren.get(0).asInstanceOf[VariantTypeNode].getClass.getSimpleName))
        case _ =>

      }


    })
  }

  @throws[IOException]
  override def visit(node: RootNode): Unit = {
    new EvtxNodeVisitor(node,event)
  }

  @throws[IOException]
  override def visit(node: TemplateInstanceNode): Unit = {
    node.getTemplateNode.accept(this)
  }

  @throws[IOException]
  override def visit(node: TemplateNode): Unit = {
    node.getChildren.forEach(child => {
      child.accept(this)
    })
  }

  @throws[IOException]
  override def visit(node: ValueNode): Unit = {
    node.getChildren.forEach(child => {
      child.accept(this)
    })
  }

  @throws[IOException]
  override def visit(node: NormalSubstitutionNode): Unit = {
    substitutions.get(node.getIndex).accept(this)
  }

  @throws[IOException]
  override def visit(node: ConditionalSubstitutionNode): Unit = {
    substitutions.get(node.getIndex).accept(this)
  }

  @throws[IOException]
  override def visit(node: VariantTypeNode): Unit = {
    node match {
        case node1: BXmlTypeNode =>
            node1.getRootNode.accept(this)
        case _ =>
    }
  }

  @throws[IOException]
  override def visit(node: AttributeNode): Unit = {
    try {
      val visitor: AttributeNodeVisitor = new AttributeNodeVisitor
      visitor.visit(node)

    } catch {
      case e: IOException =>
        System.err.println(f"${e.getCause}\n${e.getMessage}\n${e.getStackTrace.mkString("\n")}")
    }

  }

  @throws[IOException]
  override def visit(node: CloseStartElementNode): Unit = {
    //System.err.println("Close Start Node")
  }

  @throws[IOException]
  override def visit(node: CloseEmptyElementNode): Unit = {
    //System.err.println("Close Empty Start Node")
  }

  @throws[IOException]
  override def visit(node: StreamStartNode): Unit = {
    //System.err.println("Stream Start Node")
  }

  @throws[IOException]
  override def visit(node: ProcessingInstructionTargetNode): Unit = {
    //System.err.println("Processing Instruction Target Node")
  }

  @throws[IOException]
  override def visit(node: ProcessingInstructionDataNode): Unit = {
    //System.err.println("Processing Instruction Data Node")
  }

  @throws[IOException]
  override def visit(node: NameStringNode): Unit = {
    //System.err.println("Name String Node")
  }

  @throws[IOException]
  override def visit(node: EntityReferenceNode): Unit = {
    //System.err.println("Entity Reference Node")
  }

  @throws[IOException]
  override def visit(node: EndOfStreamNode): Unit = {
    //System.err.println("End of Stream Node")
  }

  @throws[IOException]
  override def visit(node: CloseElementNode): Unit = {
    //System.err.println("Close Element Node")
  }

  @throws[IOException]
  override def visit(node: CDataSectionNode): Unit = {
    //System.err.println("CData Section Node")
  }

  private class AttributeNodeVisitor extends BxmlNodeVisitor {
    private var value: String = _
    def getValue: String = value
    private var tagName: String = _
    def getTagName: String = tagName

    def this(tagName: String) {
      this
      this.tagName = tagName
    }

    @throws[IOException]
    override def visit(node: AttributeNode): Unit = {
      node.getValue.accept(this)
    }

    @throws[IOException]
    override def visit(node: ValueNode): Unit = {
      node.getChildren.forEach(child => {
        child.accept(this)
      })
    }

    @throws[IOException]
    override def visit(node: VariantTypeNode): Unit = {
      value = node.getValue
    }

    @throws[IOException]
    override def visit(node: ConditionalSubstitutionNode): Unit = {
      value = substitutions.get(node.getIndex).getValue
    }

    @throws[IOException]
    override def visit(node: NormalSubstitutionNode): Unit = {
      value = substitutions.get(node.getIndex).getValue
    }
  }
}
