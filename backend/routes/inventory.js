
import express from "express";
import jwtAuth from "../middleware/auth.js";
import InventoryModel from "../models/inventory.js";

const InventoryRouter = express.Router();


InventoryRouter.post("/add", jwtAuth, async (req, res) => {
    try {
      const userId = req.userId;
      if (!userId) {
        return res.status(401).json({ message: 'Unauthorized: No token provided' });
      }


      const {appId} = req.body;
      if (!appId) {
        return res.status(400).json({ message: 'Application ID is required' });
      }


      const newInventory = new InventoryModel(req.body);
      await newInventory.save();

      res.status(201).json({ message: 'Inventory added successfully', data: newInventory });
    } catch (error) {
      console.error('Error adding inventory:', error);
      res.status(500).json({ message: 'Internal server error', error: error.message });
    }
  });



InventoryRouter.get("/getById/:id", jwtAuth, async (req, res) => {
  try {
    const inventory = await InventoryModel.findById(req.params.id);
    if (!inventory) {
      return res.status(404).json({ message: 'Inventory not found' });
    }
    res.status(200).json({ data: inventory });
  } catch (error) {
    console.error('Error fetching inventory:', error);
    res.status(500).json({ message: 'Internal server error', error: error.message });
  }
});


InventoryRouter.put("/update/:id", jwtAuth, async (req, res) => {
    try {
      const userId = req.userId;
      if (!userId) {
        return res.status(401).json({ message: 'Unauthorized: No token provided' });
      }

      const updatedInventory = await InventoryModel.findByIdAndUpdate(
        req.params.id,
        req.body,
        { new: true, runValidators: true }
      );

      if (!updatedInventory) {
        return res.status(404).json({ message: 'Inventory not found' });
      }

      res.status(200).json({ message: 'Inventory updated successfully', data: updatedInventory });
    } catch (error) {
      console.error('Error updating inventory:', error);
      res.status(500).json({ message: 'Internal server error', error: error.message });
    }
});



InventoryRouter.delete("/delete/:id", jwtAuth, async (req, res) => {
    try {
      const userId = req.userId;
      if (!userId) {
        return res.status(401).json({ message: 'Unauthorized: No token provided' });
      }
  
      const deletedInventory = await InventoryModel.findByIdAndDelete(req.params.id);
  
      if (!deletedInventory) {
        return res.status(404).json({ message: 'Inventory not found' });
      }
  
      res.status(200).json({ message: 'Inventory deleted successfully', data: deletedInventory });
    } catch (error) {
      console.error('Error deleting inventory:', error);
      res.status(500).json({ message: 'Internal server error', error: error.message });
    }
});



  
InventoryRouter.get("/get/all", jwtAuth, async (req, res) => {
    try {
      const userId = req.userId;
      if (!userId) {
        return res.status(401).json({ message: 'Unauthorized: No token provided' });
      }
  
      const inventories = await InventoryModel.find();
  
      if (inventories.length === 0) {
        return res.status(404).json({ message: 'No inventory items found' });
      }
  
      res.status(200).json({ message: 'Inventory fetched successfully', data: inventories });
    } catch (error) {
      console.error('Error fetching inventory:', error);
      res.status(500).json({ message: 'Internal server error', error: error.message });
    }
});

export default InventoryRouter;